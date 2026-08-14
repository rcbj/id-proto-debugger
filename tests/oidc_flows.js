// File: oidc_flows.js
//
// Every OIDC authentication flow, with DPoP and without, driven through
// debugger.html / debugger2.html against EITHER OP — the mock STS and Keycloak
// both run the whole matrix:
//
//   OIDC Authorization Code Flow (code)      OIDC Hybrid (code id_token)
//   OIDC Implicit Flow (id_token token)      OIDC Hybrid (code token)
//   OIDC Implicit Flow (id_token)            OIDC Hybrid (code id_token token)
//
// One script per (flow, DPoP) pair per OP. The flows differ only in which
// artifacts come back and where from, and DPoP differs only in what rides
// along, so both are tables (FLOWS below, and the DPoP expectations in
// dpopExpectation()) rather than two dozen files that would drift apart.
//
// Two OPs, twenty-four jobs, and they answer different questions. Against the
// MOCK STS a failure is a failure in the debugger — the mock is in this
// project's control, implements all seven response types, and needs no identity
// provider, so those twelve jobs are gated on the STS alone. Against KEYCLOAK
// the same twelve ask whether any of it interoperates with a real OP, which is
// where the differences live: Keycloak gates the response types on the client's
// standardFlowEnabled/implicitFlowEnabled pair, its `sub` is a UUID rather than
// anything derived from the login name, and DPoP is a PREVIEW feature that is
// off unless the server was started with --features=dpop.
//
// Everything OP-specific arrives in the environment (DISCOVERY_ENDPOINT,
// CLIENT_ID, SCOPE, OIDC_LOGIN_USER, OIDC_EXPECT_SUB), so the assertions below
// are about the protocol and the page, not about either server.
//
// What each flow is checked for, and why these and not "a token came back":
//
//   * the authorization request the page BUILDS carries the response_type the
//     flow is named for. This is checked before the request is sent, because
//     everything downstream still looks plausible when it is wrong: the page
//     used to leave response_type at the markup's default of `code` for every
//     OIDC flow, so all five ran the Authorization Code flow and "passed"
//     anything that only looked for a token;
//   * the artifacts arrive in the FRAGMENT, and no token appears in the query.
//     OIDC section 3.2.2.5 / 3.3.2.5 require the fragment for any response
//     carrying a token, and a query-borne token leaks through Referer and
//     server logs;
//   * exactly the artifacts the response_type asks for are present, and the
//     ones it does not ask for are absent — `code token` must not carry an
//     id_token, and `id_token` must not carry an access token;
//   * the ID token verifies against jwks_uri, and carries the nonce the page
//     sent, the client as `aud` and the issuer the metadata named;
//   * `at_hash` and `c_hash` are present when an access token / code shipped
//     alongside (section 3.3.2.11), and they hash THOSE values — the detached
//     signature that makes a fragment response worth anything;
//   * for the four code-bearing flows, the code redeems at the token endpoint
//     through the page's own Token Request, and the ID token that comes back
//     verifies too.
//
// WITH DPoP (OIDC_DPOP=on) the same run additionally requires, per flow:
//
//   * a code-bearing flow to carry `dpop_jkt` on the authorization request (RFC
//     9449 section 10 — this is what binds the CODE, and it can only travel
//     there), a proof on the Token Request, and an access token whose `cnf.jkt`
//     is the RFC 7638 thumbprint of the page's key — recomputed here from the
//     public JWK rather than read from the pane, so the check is against the
//     arithmetic and not against the page agreeing with itself;
//   * an Implicit flow to bind NOTHING and to say so. There is no Token Request
//     for a proof to ride on and no code for dpop_jkt to bind: the access token
//     comes straight from the authorization endpoint in the fragment. A ticked
//     box and a ready key would otherwise read as "this will be bound", so the
//     pane is required to state the opposite, and the token is required to
//     carry no `cnf`.
//
// That asymmetry is the reason this runs as a matrix rather than as "DPoP
// works": the two Implicit flows are exactly where a DPoP implementation can
// look busy and achieve nothing.
//
// With no DISCOVERY_ENDPOINT the STS mock is located from WSTRUST_STS_URL, as
// the other STS-backed tests are. OIDC_FLOW selects the flow; OIDC_DPOP selects
// on or off (default off).

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const crypto = require("crypto");
const assert = require("assert");
const { Command, Option } = require('commander');
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oidc_flows',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// ---------------------------------------------------------------------------
// The five flows. `label` is the option text on debugger.html (the dropdown is
// what a user picks, so that is what the test picks); `responseType` is what
// the authorization request must then carry; the three booleans are what the
// authorization RESPONSE must contain, which is the same list read the other
// way round — anything not asked for must be absent.
// ---------------------------------------------------------------------------
const FLOWS = {
  oidc_authorization_code_flow: {
    label: "OIDC Authorization Code Flow(code)",
    responseType: "code",
    code: true, accessToken: false, idToken: false,
  },
  oidc_implicit_flow: {
    label: "OIDC Implicit Flow(id_token token)",
    responseType: "id_token token",
    code: false, accessToken: true, idToken: true,
  },
  oidc_implicit_flow_id_token: {
    label: "OIDC Implicit Flow(id_token)",
    responseType: "id_token",
    code: false, accessToken: false, idToken: true,
  },
  oidc_hybrid_code_id_token: {
    label: "OIDC Hybrid(code id_token)",
    responseType: "code id_token",
    code: true, accessToken: false, idToken: true,
  },
  oidc_hybrid_code_token: {
    label: "OIDC Hybrid(code token)",
    responseType: "code token",
    code: true, accessToken: true, idToken: false,
  },
  oidc_hybrid_code_id_token_token: {
    label: "OIDC Hybrid(code id_token token)",
    responseType: "code id_token token",
    code: true, accessToken: true, idToken: true,
  },
};

const wait = (milliseconds) => {
  log.debug("Entering wait().");
  log.debug("Leaving wait().");
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
};

function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function partsOf(token) {
  log.debug("Entering partsOf().");
  const parts = String(token).split(".");
  assert.strictEqual(parts.length, 3, "Expected a three-part JWS, got " +
                     parts.length + " part(s).");
  log.debug("Leaving partsOf().");
  return parts;
}
function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(b64uDecode(partsOf(token)[1]).toString("utf8"));
}
function headerOf(token) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(b64uDecode(partsOf(token)[0]).toString("utf8"));
}

// RFC 7638 section 3.1: the required members only, lexicographic, no
// whitespace. Recomputed here rather than read from the page, because "the
// token is bound to this key" has to be checked against the arithmetic — the
// three ways a thumbprint goes wrong (an extra member, the wrong order,
// whitespace) all yield a value that is stable and plausible.
function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  var canonical;
  if (jwk.kty === "EC") {
    canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === "RSA") {
    canonical = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  } else if (jwk.kty === "OKP") {
    canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error("Cannot thumbprint a " + jwk.kty + " key.");
  }
  log.debug("Leaving thumbprint().");
  return crypto.createHash("sha256").update(JSON.stringify(canonical),
                           "utf8").digest()
    .toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,
        "");
}

// What DPoP should do to THIS flow. The distinction is not on/off but on/off
// crossed with "does this flow reach the token endpoint": RFC 9449 binds a
// token issued there, and section 10's dpop_jkt binds a code. An Implicit flow
// has neither, so DPoP being on must change nothing about the wire and must be
// reported as changing nothing.
function dpopExpectation(flow, dpopOn) {
  log.debug("Entering dpopExpectation().");
  if (!dpopOn) {
    log.debug("Leaving dpopExpectation().");
    return { sendJkt: false, expectBound: false, expectNotice: false };
  }
  if (flow.code) {
    log.debug("Leaving dpopExpectation().");
    return { sendJkt: true, expectBound: true, expectNotice: false };
  }
  log.debug("Leaving dpopExpectation().");
  return { sendJkt: false, expectBound: false, expectNotice: true };
}

// OIDC section 3.3.2.11: at_hash / c_hash are the base64url of the LEFT HALF of
// the SHA-256 of the ASCII value, for an RS256 id_token. Computed here rather
// than taken from the server so the check is against the specification and not
// against the implementation being tested.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const digest = crypto.createHash("sha256").update(String(value),
      "ascii").digest();
  log.debug("Leaving halfHash().");
  return digest.slice(0, digest.length / 2).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// "The token describes the user who signed in" — asserted through the claim the
// OP publishes for it rather than through `sub`, whose FORM is the OP's own
// business (this mock namespaces it, `urn:sts-mock:user:<name>`, and a real OP
// may use a pairwise identifier that contains nothing recognisable at all).
// What matters is that some claim ties the token to the identity typed at the
// login screen, and that the same subject appears on every artifact of the
// flow.
function assertDescribesUser(claims, user, what) {
  log.debug("Entering assertDescribesUser(). what=" + what);
  assert.ok(claims.sub, what + " carries no sub.");
  // `sub` is opaque, and the two OPs this runs against prove it: the mock
  // namespaces the login name (`urn:sts-mock:user:<name>`) and Keycloak issues
  // a UUID that contains nothing recognisable. So the login name is checked
  // through `preferred_username`, and `sub` is only compared when the caller
  // was told what it should be (Keycloak's provisioning knows the UUID; the
  // mock's does not have one to give).
  if (claims.preferred_username !== undefined) {
    assert.strictEqual(claims.preferred_username, user.login,
      what + " describes " + claims.preferred_username +
          ", not the user who signed in (" +
      user.login + ").");
  } else if (!user.sub) {
    assert.ok(String(claims.sub).indexOf(user.login) >= 0,
      what + "'s sub (" + claims.sub +
          ") does not identify the user who signed in (" + user.login +
      "), and there is no preferred_username to check instead.");
  }
  if (user.sub) {
    assert.strictEqual(claims.sub, user.sub,
      what + "'s sub is " + claims.sub +
          ", not the subject the suite provisioned (" + user.sub + ").");
  }
  log.debug("Leaving assertDescribesUser().");
}

async function getJson(url) {
  log.debug("Entering getJson(). url=" + url);
  const res = await fetch(url);
  assert.ok(res.ok, "GET " + url + " answered " + res.status + ".");
  const body = await res.json();
  log.debug("Leaving getJson().");
  return body;
}

// Every token the flow produces must verify against the key the OP's own
// metadata points at. A token that merely decodes proves nothing: the fragment
// is attacker-reachable, and the signature is the only thing that says the OP
// issued what arrived.
// How a JWS `alg` maps onto node's verifier. Kept explicit rather than inferred
// because the two that are easy to get silently wrong are here: ECDSA JWS
// signatures are raw R||S (IEEE P1363) and node defaults to DER, and PS* is
// RSA-PSS with a salt the length of the digest — get either wrong and a
// perfectly good signature reports as invalid.
const JWS_ALGS = {
  RS256: { hash: "sha256" },
  RS384: { hash: "sha384" },
  RS512: { hash: "sha512" },
  PS256: { hash: "sha256", padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
  PS384: { hash: "sha384", padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
  PS512: { hash: "sha512", padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
  ES256: { hash: "sha256", dsaEncoding: "ieee-p1363" },
  ES384: { hash: "sha384", dsaEncoding: "ieee-p1363" },
  ES512: { hash: "sha512", dsaEncoding: "ieee-p1363" }
};

// Every token the flow produces must verify against the key the OP's own
// metadata points at. A token that merely decodes proves nothing: the fragment
// is attacker-reachable, and the signature is the only thing that says the OP
// issued what arrived.
//
// The key is chosen BY KID, not by position. Taking jwks.keys[0] worked against
// the mock, which publishes exactly one key, and failed every Keycloak job at
// the first token: Keycloak publishes its RSA-OAEP **encryption** key first and
// its RS256 signing key second, so the assertion said "should name the
// advertised key" about a key that signs nothing. A JWKS is a set, and its
// order means nothing.
function makeVerifier(jwks) {
  log.debug("Entering makeVerifier(). " + (jwks.keys || []).length +
            " key(s) published.");
  const byKid = {};
  (jwks.keys || []).forEach(function (k) { if (k.kid) byKid[k.kid] = k; });
  // The keys that could legitimately have signed anything: `use` absent (RFC
  // 7517 makes it optional) or "sig". Used only when a token names no kid.
  const signing = (jwks.keys || []).filter(function (k) { return !k.use ||
      k.use === "sig"; });
  log.debug("Leaving makeVerifier().");
  return function verify(token, what) {
    const parts = partsOf(token);
    const header = headerOf(token);
    const spec = JWS_ALGS[header.alg];
    assert.ok(spec, what + " is signed with " + header.alg +
              ", which this test cannot verify. " +
                    "Known: " + Object.keys(JWS_ALGS).join(", ") + ".");

    let jwk;
    if (header.kid) {
      jwk = byKid[header.kid];
      assert.ok(jwk, what + " names kid " + header.kid +
                ", which the OP's own jwks_uri does not " +
                     "publish. It publishes: " + Object.keys(byKid).join(", ") +
                         ".");
    } else {
      // No kid. Legal, and only unambiguous when one key could have signed it.
      assert.strictEqual(signing.length, 1,
        what + " carries no kid and the OP publishes " + signing.length +
            " signing keys, so which " +
        "one to verify against is a guess.");
      jwk = signing[0];
    }
    // A token signed by a key the OP published for ENCRYPTION is a real
    // finding, not a detail: it would mean the key's advertised purpose and its
    // actual use disagree.
    assert.ok(!jwk.use || jwk.use === "sig",
      what + " is signed by a key the OP publishes with use=\"" + jwk.use +
          "\", not for signing.");
    if (jwk.alg) {
      assert.strictEqual(header.alg, jwk.alg,
        what + " is signed " + header.alg +
            " with a key the OP advertises for " + jwk.alg + ".");
    }

    const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
    const params = Object.assign({ key: key }, spec);
    delete params.hash;
    assert.ok(crypto.verify(spec.hash, Buffer.from(parts[0] + "." + parts[1]),
              params,
                            b64uDecode(parts[2])),
      what + "'s signature does not verify against jwks_uri (kid " +
          (header.kid || "(none)") + ").");
    return claimsOf(token);
  };
}

// ---------------------------------------------------------------------------
// Drive debugger.html up to the point of sending the authorization request, and
// return what the page is about to send.
//
// The request preview textarea is read rather than the hidden response_type
// input, because the preview is what triggerAuthZEndpointCall() actually
// navigates to — reading the input would pass on a page that displays one thing
// and sends another.
// ---------------------------------------------------------------------------
async function prepareAuthorizationRequest(driver, flow, { clientId, scope }) {
  log.debug("Entering prepareAuthorizationRequest().");
  log.info("Entering prepareAuthorizationRequest(). flow=" + flow.label);
  const authorization_grant_type = By.id("authorization_grant_type");
  const authz_expand_button = By.id("authz_expand_button");
  const client_id_ = By.id("client_id");

  await driver.wait(until.elementLocated(authorization_grant_type), waitTime);
  // The grant dropdown lives in the Configuration Parameters pane, which
  // initializeUIPostDebuggerInitialization() COLLAPSES once discovery has run —
  // so on any visit after the first it is present and invisible, and selecting
  // from it is "element not interactable". The Authorization Code flow hid this
  // for a while: its option is the markup's default, and Selenium's Select
  // returns early when the wanted option is already selected, so the only flow
  // that never clicked was the only flow that passed.
  if (!(await driver.findElement(authorization_grant_type).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(
                      authorization_grant_type)), waitTime);
  }
  await new Select(await driver.findElement(authorization_grant_type))
                   .selectByVisibleText(flow.label);

  // Expanded only if it is not already. Once the page has been through
  // discovery it remembers (debugger_initialized) and opens this fieldset
  // itself, so a blind click COLLAPSES it and every field below becomes "not
  // interactable" — which reads as a broken page rather than as a toggle
  // pressed twice. It bit once here the moment the DPoP runs added a detour to
  // debugger2.html and back.
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  await driver.wait(until.elementLocated(client_id_), waitTime);
  if (!(await driver.findElement(client_id_).isDisplayed())) {
    await driver.findElement(authz_expand_button).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)),
                    waitTime);

  await driver.findElement(client_id_).clear();
  await driver.findElement(client_id_).sendKeys(clientId);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys(scope);
  await driver.findElement(By.id("redirect_uri")).clear();
  await driver.findElement(By.id("redirect_uri")).sendKeys(baseUrl +
                           "/callback");

  // Typing does not itself redraw the preview (it is rebuilt on change/keypress
  // handlers that clear() + sendKeys() do not always fire), so ask for it.
  await driver.executeScript(
      "debug.recalculateAuthorizationRequestDescription();");
  const preview =
      await driver.findElement(By.id("display_authz_request_form_textarea1"))
      .getAttribute("value");
  const nonce =
      await driver.findElement(By.id("nonce_field")).getAttribute("value");
  const state = await driver.findElement(By.id("state")).getAttribute("value");
  log.info("Leaving prepareAuthorizationRequest().");
  log.debug("Leaving prepareAuthorizationRequest().");
  return { preview: preview, nonce: nonce, state: state };
}

// Switch this workflow's DPoP on through its own pane on debugger2.html — the
// only place it can be switched on, which is the point of it existing — and
// return the RFC 7638 thumbprint of the key that was generated.
//
// It has to happen BEFORE the authorization request, because dpop_jkt travels
// on that request and debugger.html assembles it synchronously from storage. A
// key generated later would leave the code unbound with nothing to show for it.
async function enableDpop(driver) {
  log.debug("Entering enableDpop().");
  log.info("Entering enableDpop().");
  await driver.get(baseUrl + "/debugger2.html");
  const box = By.id("dpop_enabled");
  await driver.wait(until.elementLocated(box), waitTime * 3);
  if (!(await driver.findElement(box).isSelected())) {
    await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                               await driver.findElement(box));
    await driver.findElement(box).click();
  }
  assert.ok(await driver.findElement(box).isSelected(),
            "The DPoP checkbox did not switch on.");
  await driver.wait(async function () {
    return !!(await driver.executeScript(
      "return window.localStorage.getItem('oauth_dpop_public_jwk');"));
  }, waitTime * 5, "No DPoP key pair appeared after switching DPoP on.");
  const publicJwk = JSON.parse(await driver.executeScript(
    "return window.localStorage.getItem('oauth_dpop_public_jwk');"));
  const jkt = thumbprint(publicJwk);
  const stored = await driver.executeScript(
      "return window.localStorage.getItem('oauth_dpop_jkt');");
  assert.strictEqual(stored, jkt,
    "The page recorded jkt " + stored +
        " for a key whose RFC 7638 thumbprint is " + jkt + ".");
  log.info("Leaving enableDpop(). jkt=" + jkt);
  log.debug("Leaving enableDpop().");
  return jkt;
}

// The mock's login screen, which deliberately reuses Keycloak's field ids so
// one helper drives both. It checks no password; the username typed here is the
// identity every token then describes, which is what `user` is asserted
// against.
async function signIn(driver, user) {
  log.debug("Entering signIn().");
  log.info("Entering signIn(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 3);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    // No login screen means the authorization request was refused. The error
    // came back on the redirect, so it is on the page we are sitting on.
    const url = await driver.getCurrentUrl();
    throw new Error("The OP did not show its login screen. The " +
                    "browser is at: " + url);
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const passwordFields = await driver.findElements(By.id("password"));
  if (passwordFields.length) {
    await passwordFields[0].clear();
    await passwordFields[0].sendKeys(user);
  }
  await driver.findElement(By.id("kc-login")).click();
  log.info("Leaving signIn().");
  log.debug("Leaving signIn().");
}

// What came back, read from the browser's own URL rather than from the page's
// fields: this is the wire, and the panes are checked separately against it.
async function authorizationResponse(driver) {
  log.debug("Entering authorizationResponse().");
  await driver.wait(until.urlContains("/debugger2.html"), waitTime * 5);
  const url = await driver.getCurrentUrl();
  const parsed = new URL(url);
  const fragment = new URLSearchParams(parsed.hash.replace(/^#/, ""));
  const query = parsed.searchParams;
  const asObject = function (usp) {
    log.debug("Entering asObject().");
    const out = {};
    usp.forEach(function (v, k) { out[k] = v; });
    log.debug("Leaving asObject().");
    return out;
  };
  log.debug("Leaving authorizationResponse().");
  return { url: url, fragment: asObject(fragment), query: asObject(query) };
}

// ---------------------------------------------------------------------------
// The authorization response: the wire, then the page.
// ---------------------------------------------------------------------------
async function checkAuthorizationResponse(driver, flow, sent, expected) {
  log.debug("Entering checkAuthorizationResponse().");
  log.info("Entering checkAuthorizationResponse().");
  const response = await authorizationResponse(driver);
  log.info("Authorization response URL: " + response.url);

  // Where it arrived. Anything carrying a token is a fragment response, and a
  // token in the query is a leak rather than a variation.
  const carriesToken = flow.accessToken || flow.idToken;
  if (carriesToken) {
    assert.ok(Object.keys(response.fragment).length,
      "response_type \"" + flow.responseType +
          "\" must answer in the fragment, and the fragment is empty. " +
      "URL: " + response.url);
    assert.ok(!response.query.access_token && !response.query.id_token,
      "A token came back in the QUERY, which OIDC forbids (it leaks through " +
          "Referer and logs). URL: " +
      response.url);
  }
  const params = Object.assign({}, response.query, response.fragment);

  assert.strictEqual(params.state, sent.state,
    "The state did not come back unchanged. Sent " + sent.state + ", got " +
        params.state + ".");

  // Exactly the artifacts the response_type named, and no others.
  const artifacts = { code: flow.code, access_token: flow.accessToken,
      id_token: flow.idToken };
  Object.keys(artifacts).forEach(function (name) {
    if (artifacts[name]) {
      assert.ok(params[name],
        "response_type \"" + flow.responseType + "\" must return " + name +
            ", and none arrived. " +
        "Got: " + Object.keys(params).join(", ") + ".");
    } else {
      assert.ok(!params[name],
        "response_type \"" + flow.responseType + "\" must NOT return " + name +
            ", and one arrived.");
    }
  });
  log.info("[" + flow.responseType + "] OK — the response arrived " +
           (carriesToken ? "in the fragment" : "in the query") +
            " with exactly " +
           Object.keys(artifacts).filter(function (k) { return artifacts[k]; })
                       .join(", ") + ".");

  // The ID token, against the specification's own rules.
  if (flow.idToken) {
    const claims = expected.verify(params.id_token,
        "the authorization endpoint's ID token");
    assert.strictEqual(claims.iss, expected.issuer, "The ID token's iss is " +
                       claims.iss + ".");
    assert.strictEqual(claims.aud, expected.clientId, "The ID token's aud is " +
                       claims.aud + ".");
    assertDescribesUser(claims, expected.user, "The ID token");
    assert.strictEqual(claims.nonce, sent.nonce,
      "The ID token's nonce is " + claims.nonce +
          ", not the one the page sent (" + sent.nonce + "). " +
      "Without that, a token from another session replays into this one.");
    if (flow.accessToken) {
      assert.strictEqual(claims.at_hash, halfHash(params.access_token),
        "at_hash does not match the access token that came with it (OIDC " +
            "3.3.2.11).");
    }
    if (flow.code) {
      assert.strictEqual(claims.c_hash, halfHash(params.code),
        "c_hash does not match the code that came with it (OIDC 3.3.2.11).");
    }
    log.info("[" + flow.responseType +
             "] OK — the ID token verifies against jwks_uri, names " +
             claims.sub +
             ", carries the nonce" +
             (flow.accessToken ? ", at_hash matches the access token" : "") +
             (flow.code ? ", c_hash matches the code" : "") + ".");
  }

  // And the access token, when the flow returns one. When both came back they
  // must describe the SAME subject: at_hash ties the two together
  // cryptographically, and this is the same statement read semantically.
  if (flow.accessToken) {
    const claims = expected.verify(params.access_token,
        "the authorization endpoint's access token");
    assert.strictEqual(claims.iss, expected.issuer,
                       "The access token's iss is " + claims.iss + ".");
    assertDescribesUser(claims, expected.user, "The access token");
    if (flow.idToken) {
      assert.strictEqual(claims.sub, claimsOf(params.id_token).sub,
        "The access token and the ID token from the same response describe " +
            "different subjects.");
    }
    log.info("[" + flow.responseType +
             "] OK — the access token verifies against jwks_uri" +
             (flow.idToken ?
              " and names the same subject as the ID token" : "") + ".");
  }
  log.info("Leaving checkAuthorizationResponse().");
  log.debug("Leaving checkAuthorizationResponse().");
  return params;
}

// ---------------------------------------------------------------------------
// The page's own display of that response. Separate from the wire check above
// because the debugger's product IS the display: a flow that works and shows
// nothing is still broken here.
// ---------------------------------------------------------------------------
async function checkPanesShowArtifacts(driver, flow, params) {
  log.debug("Entering checkPanesShowArtifacts().");
  log.info("Entering checkPanesShowArtifacts().");
  // Scoped to the two panes that report the authorization response, and NOT to
  // the page at large. Searching every field on the page passes for the wrong
  // reason: debugger2 also writes the access token to localStorage, from where
  // the revocation pane prefills its own field — so a mutation that blanked the
  // results pane entirely was not caught until this was narrowed. The ids
  // differ per flow (the panes are generated per grant type), so the fields are
  // collected from the containers rather than named one by one.
  const shown = await driver.executeScript(
    "var out = { panes: [], code: null };" +
    "['authorization_endpoint_result'," +
        "'authorization_endpoint_id_token_result']" +
    "  .forEach(function(id){ var pane = document.getElementById(id); if " +
        "(!pane) return;" +
    "    Array.prototype.forEach.call(pane.querySelectorAll('textarea,input')," +
    "      function(e){ out.panes.push(e.value); }); });" +
    "var codeField = document.getElementById('code');" +
    "if (codeField) out.code = codeField.value;" +
    "return out;");

  if (flow.accessToken) {
    assert.ok(shown.panes.indexOf(params.access_token) >= 0,
      "The access token came back, and the Authorization Endpoint Results " +
          "panes do not show it. " +
      "They hold: " + JSON.stringify(shown.panes) + ".");
  }
  if (flow.idToken) {
    assert.ok(shown.panes.indexOf(params.id_token) >= 0,
      "The ID token came back, and the Authorization Endpoint Results panes " +
          "do not show it. " +
      "They hold: " + JSON.stringify(shown.panes) + ".");
  }
  if (flow.code) {
    assert.ok(shown.code === params.code,
      "The authorization code came back in the fragment but the Token " +
          "Request's code field holds \"" +
      shown.code + "\". Nothing can be exchanged from there.");
  }
  log.info("[" + flow.responseType +
           "] OK — the page shows every artifact that arrived.");
  log.info("Leaving checkPanesShowArtifacts().");
  log.debug("Leaving checkPanesShowArtifacts().");
}

// ---------------------------------------------------------------------------
// DPoP on a flow with no Token Request: the page must say that nothing will be
// bound.
//
// This is the assertion that makes the Implicit half of the matrix worth
// running. Switching DPoP on and watching a key appear looks like success; on
// these two flows it achieves nothing, because the access token is minted by
// the authorization endpoint and RFC 9449 binds tokens minted at the token
// endpoint. A pane that showed a ready key and said nothing else would be
// telling the user their token is sender-constrained when it is not.
// ---------------------------------------------------------------------------
async function checkNoTokenRequestNotice(driver, flow) {
  log.debug("Entering checkNoTokenRequestNotice().");
  log.info("Entering checkNoTokenRequestNotice().");
  const status = await driver.findElements(By.id("dpop_status"));
  assert.ok(status.length, "debugger2.html has no DPoP status line.");
  // Read from the DOM rather than getText(): the pane sits inside the Token
  // Request fieldset, which these flows collapse, and an invisible element's
  // getText() is "" — which would pass this check by saying nothing at all.
  const text = await driver.executeScript(
    "var e = document.getElementById('dpop_status'); return e ? " +
        "e.textContent : '';");
  assert.ok(/no Token Request/i.test(text),
    "DPoP is on and the " + flow.label +
        " flow cannot use it, and the pane does not say so. " +
    "It says: \"" + text + "\".");
  assert.ok(/RFC 9449/.test(text),
    "The notice should name the specification it is explaining. It says: \"" +
        text + "\".");
  log.info("[" + flow.responseType +
           "/dpop-on] OK — the pane states that this flow has no Token " +
           "Request for a proof to ride on, so nothing is sender-constrained.");
  log.info("Leaving checkNoTokenRequestNotice().");
  log.debug("Leaving checkNoTokenRequestNotice().");
}

// ---------------------------------------------------------------------------
// The code half of a code-bearing flow: redeem it through the page's Token
// Request. With `dpopJkt` set, the token that comes back must be bound to it.
// ---------------------------------------------------------------------------
async function exchangeCode(driver, flow, sent, expected, { dpopJkt } = {}) {
  log.debug("Entering exchangeCode().");
  log.info("Entering exchangeCode().");
  const token_client_id = By.id("token_client_id");
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)),
                    waitTime);

  // Make the Token Request from the BROWSER rather than through the api proxy.
  // Two reasons, and the first is what keeps these five jobs runnable wherever
  // the suite runs: the browser-direct call goes straight to the OP, so this
  // test needs the client and the STS and nothing else — no api service, and no
  // api CORS allow-list that has to name whichever origin the debugger is
  // served from. The second is that it is the leg that carries a DPoP proof
  // when one is in play; the proxied call cannot, and debugger2.html says so in
  // its banner. Clicked rather than set in storage: useFrontEnd is only
  // assigned by setInitiateFromEnd(), which runs on the radio's own click
  // handler.
  const frontEnd =
      await driver.findElements(By.id("token_initiateFromFrontEnd"));
  assert.ok(frontEnd.length,
      "debugger2.html has no token_initiateFromFrontEnd radio to select.");
  await driver.executeScript("arguments[0].scrollIntoView({block: 'center'});",
                             frontEnd[0]);
  await frontEnd[0].click();
  assert.ok(await frontEnd[0].isSelected(),
    "The browser-direct radio did not take, so the Token Request would go " +
        "through the api.");
  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(expected.clientId);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope")).sendKeys(expected.scope);
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(baseUrl +
                           "/callback");
  await driver.findElement(By.className("token_btn")).click();

  const tokenField = By.id("token_access_token");
  const errorField = By.id("display_token_error_form_textarea1");
  let value = "";
  try {
    await driver.wait(async function () {
      const fields = await driver.findElements(tokenField);
      if (fields.length) {
        value = await fields[0].getAttribute("value");
        if (value && value.split(".").length === 3) return true;
      }
      const errors = await driver.findElements(errorField);
      if (errors.length) {
        const text = await errors[0].getAttribute("value");
        if (text && text.trim()) throw new Error("The token endpoint refused " +
            "the code: " + text);
      }
      return false;
    }, waitTime * 5);
  } catch (e) {
    // A `status: 0` here is not the OP refusing anything — it is the browser
    // never sending the request. The Token Request goes browser-direct, and
    // with DPoP on it carries a `DPoP` header, which makes it a non-simple
    // cross-origin request: the OP must both allow this origin (Keycloak's
    // webOrigins) and name DPoP in Access-Control-Allow-Headers on the
    // preflight. Worth saying, because the raw symptom names neither.
    const hint = /status: 0/.test(e.message)
      ? " The request never left the browser (status 0), which is a CORS " +
          "problem rather than a " +
        "protocol one: check that the OP allows this origin, and — with DPoP " +
            "on — that its " +
        "preflight response allows the DPoP request header."
      : "";
    throw new Error("Exchanging the authorization code produced no " +
                    "access token. " + e.message + hint);
  }

  const claims = expected.verify(value, "the token endpoint's access token");
  assert.strictEqual(claims.iss, expected.issuer,
                     "The exchanged access token's iss is " + claims.iss + ".");
  assertDescribesUser(claims, expected.user, "The exchanged access token");

  // The binding, in both directions. "Bound" is read off the token's own
  // cnf.jkt rather than off the fact that a proof was sent, because an
  // authorization server that ignores DPoP answers with a perfectly ordinary
  // Bearer token and the client cannot tell the difference any other way.
  if (dpopJkt) {
    assert.ok(claims.cnf && claims.cnf.jkt,
      "A DPoP proof was sent with the Token Request and the access token " +
          "came back with no " +
      "cnf.jkt — it is an ordinary Bearer token, and nothing said so.");
    assert.strictEqual(claims.cnf.jkt, dpopJkt,
      "The token is bound to " + claims.cnf.jkt + ", not to this page's key (" +
          dpopJkt + ").");
    // And the page has to report it, beside the token it is about.
    const verdict = await driver.findElements(By.id("dpop_result_status"));
    assert.ok(verdict.length,
      "The token came back sender-constrained and the results pane says " +
          "nothing about it.");
    assert.ok(await verdict[0].isDisplayed(),
              "The binding verdict is in the page but not visible.");
    const verdictText = await verdict[0].getText();
    assert.ok(/sender-constrained/i.test(verdictText),
      "The results pane does not report the binding. It says: \"" +
          verdictText + "\".");
    log.info("[" + flow.responseType +
             "/dpop-on] OK — the exchanged token carries cnf.jkt = the " +
             "thumbprint of this page's key, and the results pane says so.");
  } else {
    assert.ok(!claims.cnf,
      "DPoP is off for this workflow and the exchanged access token came " +
          "back sender-constrained " +
      "(cnf=" + JSON.stringify(claims.cnf) + ").");
  }

  // The token response's own ID token — a second one, freshly minted, which
  // must carry the same nonce as the authorization request that started this.
  const idFields = await driver.findElements(By.id("token_id_token"));
  assert.ok(idFields.length,
            "The Token Endpoint results pane has no ID token field.");
  const idValue = await idFields[0].getAttribute("value");
  assert.ok(idValue && idValue.split(".").length === 3,
    "The token endpoint returned no ID token for an openid request. Field " +
        "holds: \"" + idValue + "\".");
  const idClaims = expected.verify(idValue, "the token endpoint's ID token");
  assert.strictEqual(idClaims.nonce, sent.nonce,
    "The token endpoint's ID token carries nonce " + idClaims.nonce +
        ", not the one the page sent.");
  log.info("[" + flow.responseType + "] OK — the code redeemed at the token " +
           "endpoint, and both tokens verify.");
  log.info("Leaving exchangeCode().");
  log.debug("Leaving exchangeCode().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless. The tests image pins Chrome 121, where plain
    // --headless selects the OLD headless implementation — and in that one
    // --unsafely-treat-insecure-origin-as-secure has no effect, so on the
    // containerized suite's http://client:3000 origin window.crypto.subtle
    // stays undefined and the DPoP key pair is never generated. The symptom is
    // a timeout waiting for a key, naming nothing about crypto or headless
    // mode. Invisible locally: from Chrome 132 the old mode is gone and
    // --headless IS the new one, so this passes on a modern browser and fails
    // only in CI.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm.
  options.addArguments("--disable-dev-shm-usage");
  // The private-network flags AND the secure-context relaxing, from one place.
  // The second is what this test cannot run without in the containerized suite:
  // the debugger is served from http://client:3000 — plain HTTP on a DNS name,
  // which is NOT a secure context — so window.crypto.subtle is undefined there
  // and the DPoP key pair can never be generated. The failure would be a
  // timeout waiting for a key, naming nothing about crypto or about the origin.
  // See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    const flowKey = process.env.OIDC_FLOW;
    assert(flowKey, "OIDC_FLOW environment variable is not set (one of: " +
                    Object.keys(FLOWS).join(", ") + ").");
    const flow = FLOWS[flowKey];
    assert(flow, "OIDC_FLOW=\"" + flowKey + "\" is not one of: " +
           Object.keys(FLOWS).join(", ") + ".");

    const stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
    const stsBase = stsUrl.replace(/\/sts\/?$/, "");
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT ||
                               (stsBase + "/.well-known/openid-configuration");
    const clientId = process.env.CLIENT_ID || "oidc-flow-test-client";
    const scope = process.env.SCOPE || "openid profile email";
    // Deliberately NOT process.env.USER: every shell sets that, so a standalone
    // run signed in as whoever started it and the assertions then described
    // that person. The mock accepts any username and checks no password, so the
    // test picks its own — OIDC_FLOW_USER only exists to override it. Who signs
    // in, and (when the suite knows it) the subject identifier the tokens must
    // then carry. Keycloak's provisioning exports both — the login name and the
    // UUID — and they are different strings; the mock has only the one.
    // Deliberately NOT process.env.USER for the login name: every shell sets
    // that, so a standalone run signed in as whoever started it.
    const user = {
      login: process.env.OIDC_LOGIN_USER || process.env.OIDC_FLOW_USER ||
          "oidcflowuser",
      sub: process.env.OIDC_EXPECT_SUB || ""
    };
    const dpopSetting = String(process.env.OIDC_DPOP || "off").toLowerCase();
    assert(["on", "off"].indexOf(dpopSetting) >= 0,
      "OIDC_DPOP must be \"on\" or \"off\", not \"" + process.env.OIDC_DPOP +
          "\".");
    const dpopOn = dpopSetting === "on";
    const dpop = dpopExpectation(flow, dpopOn);

    // The metadata is read here as well as by the page, because every assertion
    // below is against what the OP itself advertises rather than against a URL
    // written down in this file.
    const metadata = await getJson(discovery_endpoint);
    assert.ok(metadata.response_types_supported.indexOf(flow.responseType) >= 0,
      "The OP does not advertise response_type \"" + flow.responseType +
          "\", so this flow cannot be " +
      "tested against it. It advertises: " +
          metadata.response_types_supported.join(" | ") + ".");
    // An OP that does not support DPoP answers every proof with a perfectly
    // ordinary Bearer token, so a DPoP-on job against one fails at the very end
    // with "the token came back unbound" — which reads as a client bug. RFC
    // 9449 section 5.1 makes dpop_signing_alg_values_supported the way to
    // discover support, so it is checked first and the failure names the cause.
    // Keycloak needs --features=dpop (it is a preview feature); the mock always
    // has it.
    if (dpopOn) {
      assert.ok((metadata.dpop_signing_alg_values_supported || []).length,
        "This OP does not advertise dpop_signing_alg_values_supported, so it " +
            "does not support DPoP " +
        "(RFC 9449 section 5.1) and this job cannot mean anything. For " +
            "Keycloak, start it with " +
        "--features=dpop — DPoP is a preview feature and is off by default. " +
            "Metadata: " +
        discovery_endpoint);
      log.info("The OP advertises DPoP: " +
               metadata.dpop_signing_alg_values_supported.join(" | ") + ".");
    }
    const jwks = await getJson(metadata.jwks_uri);
    const expected = {
      issuer: metadata.issuer,
      clientId: clientId,
      scope: scope,
      user: user,
      verify: makeVerifier(jwks),
    };

    log.info("Running the " + flow.label + " flow against " + metadata.issuer +
             ", DPoP " + dpopSetting + ", signing in as " + user.login + ".");
    await driver.manage().deleteAllCookies();
    await driver.get(baseUrl + "/debugger.html");
    // A previous flow's state in localStorage would otherwise decide which
    // panes debugger2.html draws, which is exactly what this test is reading.
    await driver.executeScript("window.localStorage.clear();");
    await driver.get(baseUrl + "/debugger.html");

    await populateMetadata(driver, discovery_endpoint);

    // DPoP is switched on — when it is — BEFORE the authorization request,
    // since dpop_jkt can only travel on that request. Storage was cleared just
    // above, so this is also what proves the switch defaults to off: with
    // OIDC_DPOP=off nothing here runs and the assertions below require an
    // unbound exchange.
    var dpopJkt = "";
    if (dpopOn) {
      dpopJkt = await enableDpop(driver);
      // Back to the page that builds the authorization request.
      await driver.get(baseUrl + "/debugger.html");
    }
    const sent = await prepareAuthorizationRequest(driver, flow,
        { clientId: clientId, scope: scope });

    // The check that has to come first: what the page is about to send.
    const sentResponseType = (sent.preview.match(/response_type=([^&\n]*)/) ||
        [])[1];
    assert.strictEqual(sentResponseType, flow.responseType,
      "The page is about to send response_type=\"" + sentResponseType +
          "\" for the " + flow.label +
      " flow, which asks for \"" + flow.responseType +
          "\". The request preview reads:\n" + sent.preview);
    assert.ok(sent.nonce, "The authorization request carries no nonce, which " +
              "OIDC requires for this flow.");
    assert.ok(sent.preview.indexOf("nonce=" + sent.nonce) >= 0,
      "The nonce field holds " + sent.nonce +
          " but the request being sent does not carry it.");
    log.info("[" + flow.responseType + "] OK — the page sends response_type=" +
             sentResponseType +
             " with a nonce.");

    // RFC 9449 section 10 on the authorization request. Asserted in BOTH
    // directions: absent when DPoP is off (or when the flow has no code to
    // bind), and exactly this key's thumbprint when it should be there. A
    // dpop_jkt sent for the wrong key is worse than none — the code becomes
    // unredeemable.
    const sentJkt = (sent.preview.match(/dpop_jkt=([^&\n]*)/) || [])[1] || "";
    if (dpop.sendJkt) {
      assert.strictEqual(sentJkt, dpopJkt,
        "The authorization request should carry dpop_jkt=" + dpopJkt +
            " and carries \"" + sentJkt +
        "\". Request:\n" + sent.preview);
      log.info("[" + flow.responseType + "/dpop-" + dpopSetting +
               "] OK — the authorization request binds the code with " +
                   "dpop_jkt.");
    } else {
      assert.strictEqual(sentJkt, "",
        "The authorization request carries dpop_jkt=" + sentJkt +
            ", and it should not: " +
        (dpopOn ? "this flow returns no code for it to bind." : "DPoP is off " +
         "for this workflow."));
      log.info("[" + flow.responseType + "/dpop-" + dpopSetting +
               "] OK — no dpop_jkt on the authorization request.");
    }

    await driver.findElement(By.css(
                             "input[type=\"submit\"][value=\"Authorize\"]"))
                             .click();
    await signIn(driver, user.login);

    const params = await checkAuthorizationResponse(driver, flow, sent,
        expected);
    await checkPanesShowArtifacts(driver, flow, params);

    // An access token issued by the AUTHORIZATION endpoint is never DPoP-bound,
    // whatever the switch says: there was no request for a proof to ride on.
    // This is the assertion that stops "DPoP is on" from being read as
    // "everything is bound now".
    if (flow.accessToken) {
      const authzClaims = claimsOf(params.access_token);
      assert.ok(!authzClaims.cnf,
        "The access token from the AUTHORIZATION endpoint carries cnf=" +
        JSON.stringify(authzClaims.cnf) +
                       ". Nothing proved possession of a key on that leg — " +
        "the token arrived in the fragment — so a binding here would be a " +
            "claim with nothing " +
        "behind it.");
    }
    if (dpop.expectNotice) {
      await checkNoTokenRequestNotice(driver, flow);
    }

    if (flow.code) {
      await exchangeCode(driver, flow, sent, expected,
                         { dpopJkt: dpop.expectBound ? dpopJkt : "" });
    }

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oidc_flows')
  .description("Run one of the five non-Authorization-Code OIDC flows " +
      "against the mock STS.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-f, --flow <flow>",
      "Which flow to run (overrides OIDC_FLOW): " +
          Object.keys(FLOWS).join(", "))
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.flow) {
      process.env.OIDC_FLOW = options.flow;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
