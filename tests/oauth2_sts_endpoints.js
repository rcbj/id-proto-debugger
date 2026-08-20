// File: oauth2_sts_endpoints.js
//
// The mock authorization server the STS service hosts: every endpoint its
// RFC 8414 metadata advertises answers, and every token it issues verifies
// against the JWKS that same document points at.
//
// No browser — this drives the endpoints directly:
//
//   * every advertised endpoint and document URL responds;
//   * the authorization endpoint authenticates the user at a login screen
//     first, then issues a code, honours state, reports errors the way OAuth
//     2.0 says to, and puts tokens in the fragment (never the query) for the
//     implicit and hybrid response types;
//   * whatever username is typed into that screen is the identity every token,
//     and introspection, then describes;
//   * the token endpoint implements exactly the grants the metadata advertises
//     — authorization_code (with PKCE), refresh_token, client_credentials,
//     password and token-exchange — and refuses anything else;
//   * every access / ID / refresh token is an RS256 JWT whose signature
//     verifies against jwks_uri, with the claims OIDC asks for (aud, nonce,
//     at_hash, c_hash);
//   * a bad code_verifier is refused WITHOUT consuming the code, and a code
//     that was redeemed is single use in the way this mock relaxes it: the
//     identical request gets the identical tokens back for the rest of the
//     code's lifetime, and any other request for that code is refused with the
//     difference named;
//   * introspection tells the truth, revocation takes effect, and a revoked
//     refresh token stops working;
//   * dynamic client registration (RFC 7591) and its management calls
//     (RFC 7592) work and are protected by the registration access token.
//
// The STS mock is located from WSTRUST_STS_URL, as the other STS-backed tests
// are; OAUTH_METADATA_URL overrides the metadata URL outright.

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require('commander');
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_sts_endpoints',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var stsBase = stsUrl.replace(/\/sts\/?$/, "");
var metadataUrl = process.env.OAUTH_METADATA_URL || (stsBase +
    "/.well-known/oauth-authorization-server");

// Somewhere for the authorization endpoint to redirect to. Nothing listens
// there — the redirect is read, not followed.
var REDIRECT_URI = "http://localhost:9999/callback";
var CLIENT_ID = "sts-endpoint-test-client";
// The identity the password grant presents. Generated per run rather than
// fixed: this mock checks no password (only the reserved string "invalid" is
// refused) and records every authentication against the name presented, so a
// name shared with every other test makes its users page and audit log
// unreadable. The prefix names this file.
var RO_USER = process.env.STS_RO_USER || usernameFor("oauth2-sts-endpoints");

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(b64uDecode(String(token).split(".")[1]).toString("utf8"));
}
function headerOf(token) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(b64uDecode(String(token).split(".")[0]).toString("utf8"));
}
function form(obj) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(obj).toString();
}

function get(url, options) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetch(url, Object.assign({ redirect: "manual" }, options || {}));
}
async function postForm(url, body, headers) {
  log.debug("Entering postForm().");
  const r = await fetch(url, {
    method: "POST",
    headers: Object.assign({
        "Content-Type": "application/x-www-form-urlencoded" }, headers || {}),
    body: form(body)
  });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    // Not JSON: the caller gets the raw text instead.
  }
  log.debug("Leaving postForm().");
  return { status: r.status, body: json, raw: text };
}

// OIDC section 3.1.3.6: at_hash / c_hash is base64url(left half of SHA-256).
function halfHash(value) {
  log.debug("Entering halfHash().");
  const h = crypto.createHash("sha256").update(String(value), "ascii").digest();
  log.debug("Leaving halfHash().");
  return b64u(h.subarray(0, h.length / 2));
}

// Every token this server issues must verify against the key its own metadata
// advertises — an unverifiable "token" would make every other check hollow.
function makeVerifier(jwks) {
  log.debug("Entering makeVerifier().");
  const key = crypto.createPublicKey({ key: jwks.keys[0], format: "jwk" });
  log.debug("Leaving makeVerifier().");
  return function (token, what) {
    const parts = String(token).split(".");
    assert.strictEqual(parts.length, 3, what +
                       " should be a three-part JWS. Got: " +
                       String(token).slice(0, 40));
    const header = headerOf(token);
    assert.strictEqual(header.alg, "RS256", what +
                       " should be signed RS256, got " + header.alg + ".");
    assert.strictEqual(header.kid, jwks.keys[0].kid,
      what + " should name the advertised key (kid " + jwks.keys[0].kid +
          "), got " + header.kid + ".");
    assert.ok(crypto.verify("sha256", Buffer.from(parts[0] + "." + parts[1]),
              key, b64uDecode(parts[2])),
      what + "'s signature does not verify against jwks_uri.");
    return claimsOf(token);
  };
}

function parseRedirect(location) {
  log.debug("Entering parseRedirect().");
  const hashAt = location.indexOf("#");
  log.debug("Leaving parseRedirect().");
  return {
    location: location,
    fragment: hashAt >= 0,
    params: new URLSearchParams(hashAt >= 0 ? location.slice(hashAt +
                                1) : new URL(location).search)
  };
}

// Start an authorization request and drive it to the client's redirect_uri,
// which means going through the AUTHENTICATION SERVICE the way a browser would.
// The login screen is its own endpoint since 2026-08-19, so the first answer is
// a redirect rather than a form:
//
//   GET  /oauth2/authorize   -> 302 to /authn/login?authn=...
//   GET  /authn/login        -> the form
//   POST /authn/login        -> back to /oauth2/authorize, with a session cookie
//   GET  /oauth2/authorize   -> the authorization response
//
// options.username  who to sign in as (their name ends up in the tokens)
// options.cookie    reuse an existing session instead of signing in again
async function authorize(meta, params, options) {
  log.debug("Entering authorize().");
  options = options || {};
  const username = options.username || "test-user";
  let r = await get(meta.authorization_endpoint + "?" + form(params),
    options.cookie ? { headers: { cookie: options.cookie } } : {});

  // Every answer here is a 302 now, so which one it is has to be read off the
  // Location: the authentication service is on this origin and everything else
  // — an error, or a session that skipped the prompt — goes to the client.
  assert.strictEqual(r.status, 302,
    "the authorization endpoint should redirect, either to the client or to " +
        "the authentication service, got HTTP " + r.status + ".");
  const first = r.headers.get("location");
  if (first.indexOf("/authn/") !== 0 &&
      first.indexOf(meta.issuer + "/authn/") !== 0) {
    const out = parseRedirect(first);
    out.prompted = false;
    out.cookie = options.cookie;
    log.debug("Leaving authorize().");
    return out;
  }

  // The screen, at its own URL. It is a GET, which is what makes it a service
  // rather than a page rendered inside somebody else's endpoint.
  r = await get(first.indexOf("http") === 0 ? first : meta.issuer + first,
    options.cookie ? { headers: { cookie: options.cookie } } : {});
  assert.strictEqual(r.status, 200,
    "the authentication service should show the sign-in screen, got HTTP " +
        r.status + ".");
  const page = await r.text();
  const authnId = (page.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");

  r = await fetch(meta.issuer + "/authn/login", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ authn_id: authnId, username: username,
               password: options.password || "any-password",
                 action: options.action || "login" })
  });
  // The sign-in form is a POST and the answer to it is a redirect. WHICH
  // redirect is the interesting part, and it is asserted the way RFC 9700
  // section 4.12 states it rather than as one exact code: 303 is what the mock
  // sends now and what the BCP asks for, 302 is what it sent before and what
  // most servers send, and **307 is the one that is forbidden** — it replays
  // the method and the body, which on this request is the username and
  // password, onto whatever the redirect names. Pinning 302 exactly made this
  // fail the day the mock started doing the more correct thing, and it never
  // checked the code the specification actually cares about.
  assert.ok(r.status === 303 || r.status === 302,
    "submitting the sign-in form should redirect, got HTTP " + r.status + ".");
  assert.notStrictEqual(r.status, 307,
    "RFC 9700 section 4.12: a credential-bearing POST must not be answered " +
    "with 307, which replays the method and the body onto the next hop.");
  const cookie = String(r.headers.get("set-cookie") || "").split(";")[0];
  let next = r.headers.get("location");
  if (next.indexOf("http") !== 0) next = meta.issuer + next;

  // Cancel comes back to the authorization endpoint as well, carrying
  // authn_error rather than being answered at the screen: the service does not
  // know what an OAuth refusal looks like, and in response_mode=form_post it is
  // not a redirect at all. So the outcome is read from the SECOND hop, and the
  // absence of a session cookie is what says nobody signed in.
  const refused = /[?&]authn_error=/.test(next);
  assert.ok(refused || cookie, "signing in should establish a session.");
  r = await get(next, cookie ? { headers: { cookie: cookie } } : {});
  if (refused) {
    const out = parseRedirect(r.headers.get("location"));
    out.prompted = true;
    out.page = page;
    log.debug("Leaving authorize(). The user refused at the sign-in screen.");
    return out;
  }
  assert.strictEqual(r.status, 302,
    "the authorization endpoint should answer after the login, got HTTP " +
        r.status + ".");
  const out = parseRedirect(r.headers.get("location"));
  out.prompted = true;
  out.cookie = cookie;
  out.username = username;
  out.page = page;
  out.viaAuthorize = next;
  log.debug("Leaving authorize().");
  return out;
}

// ---------------------------------------------------------------------------
// The login screen: the authorization endpoint is a browser flow, so an
// unauthenticated request has to authenticate the user before it issues
// anything — and the username typed in is the identity every token describes.
// ---------------------------------------------------------------------------
async function testLoginScreen(meta, verify) {
  log.debug("Entering testLoginScreen().");
  log.info("=== The login screen ===");
  const params = {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid profile email", state: "login-state", nonce: "login-nonce",
    login_hint: "prefilled-user"
  };

  // 1. The unauthenticated request is handed to the authentication service —
  //    a redirect to an endpoint of its own, not a form in this endpoint's body.
  const first = await get(meta.authorization_endpoint + "?" + form(params));
  assert.strictEqual(first.status, 302,
    "an unauthenticated request should be sent to the authentication " +
        "service, got HTTP " + first.status + ".");
  const toService = first.headers.get("location");
  assert.ok(/^(https?:\/\/[^/]+)?\/authn\/login\?authn=[^&]+$/.test(toService),
    "and the redirect should name the sign-in screen with the id of the " +
        "request it stashed. Got: " + toService);
  assert.ok(!/code=/.test(toService),
    "nothing should be issued on the way to signing in.");

  const screen = await get(toService.indexOf("http") === 0 ? toService
    : meta.issuer + toService);
  assert.strictEqual(screen.status, 200,
      "the sign-in screen should be served at its own URL.");
  assert.ok(/text\/html/.test(screen.headers.get("content-type") || ""),
            "the sign-in screen should be HTML.");
  const page = await screen.text();
  assert.ok(/<form[^>]+action="\/authn\/login"/.test(page),
            "the sign-in screen should post to /authn/login.");
  assert.ok(/id="username"/.test(page) && /id="password"/.test(page),
    "the sign-in screen should ask for a username and a password.");
  assert.ok(/name="authn_id" value="[^"]+"/.test(page),
            "the form should carry the request it interrupted.");
  assert.ok(page.indexOf('value="prefilled-user"') !== -1,
    "login_hint should pre-fill the username field.");
  assert.ok(page.indexOf(CLIENT_ID) !== -1 && page.indexOf(REDIRECT_URI) !== -1,
    "the sign-in screen should say which client and redirect_uri it is " +
    "signing in for — the service knows nothing about OAuth, so those rows " +
        "are what the authorization endpoint passed it.");
  assert.ok(!/code=/.test(page),
            "nothing should be issued before the user signs in.");
  log.info("[login] OK — an unauthenticated authorization request is sent to " +
           "the authentication service, which shows the form.");

  // 2. Signing in leads back to the authorization endpoint, then to the client.
  const username = "signed.in.user";
  const authz = await authorize(meta, params, { username: username });
  assert.ok(authz.viaAuthorize &&
            authz.viaAuthorize.indexOf(meta.authorization_endpoint) === 0,
    "submitting the login form should redirect back to the authorization " +
        "endpoint. Got: " + authz.viaAuthorize);
  assert.ok(authz.viaAuthorize.indexOf("prompt") < 0,
    "the redirect back must drop prompt, or the login screen would loop.");
  assert.ok(authz.location.indexOf(REDIRECT_URI) === 0,
    "the authorization response should go to the client's redirect_uri. Got: " +
        authz.location);
  const code = authz.params.get("code");
  assert.ok(code, "no authorization code came back after the login.");
  assert.strictEqual(authz.params.get("state"), "login-state",
                     "state must survive the login round trip.");

  // 3. Every token then describes the user who typed their name in.
  const set = (await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code, client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI
  })).body;
  const at = verify(set.access_token, "the access token");
  const it = verify(set.id_token, "the ID token");
  assert.strictEqual(at.username, username,
    "the access token should name the user who signed in. Got: " + at.username);
  assert.ok(at.sub.indexOf(username) !== -1,
    "the subject should be derived from the username signed in with. Got: " +
        at.sub);
  assert.strictEqual(it.preferred_username, username,
                     "the ID token should name that user too.");
  assert.strictEqual(it.given_name, username,
                     "the ID token's claims should describe that user.");
  assert.ok(String(it.email).indexOf(username) === 0,
    "the ID token's email should be derived from the username. Got: " +
        it.email);
  assert.strictEqual(it.nonce, "login-nonce",
                     "the nonce must survive the login round trip.");
  assert.ok(it.auth_time > 0,
            "the ID token should say when the user authenticated.");

  const ins = await postForm(meta.introspection_endpoint,
      { token: set.access_token });
  assert.strictEqual(ins.body.username, username,
                     "introspection should report that user as well.");
  const refreshed = await postForm(meta.token_endpoint, {
    grant_type: "refresh_token", refresh_token: set.refresh_token,
        client_id: CLIENT_ID
  });
  assert.strictEqual(claimsOf(refreshed.body.id_token).preferred_username,
                     username,
    "refreshing should keep describing the user who signed in.");
  log.info('[login] OK — the tokens describe "' + username +
           '", the name that was typed in.');

  // 4. A different user gets a different identity — nothing is hard-coded.
  const other = await authorize(meta, params, { username: "someone.else" });
  const otherSet = (await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: other.params.get("code"),
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI
  })).body;
  assert.strictEqual(claimsOf(otherSet.access_token).username, "someone.else",
    "a second sign-in should produce that second identity.");
  assert.notStrictEqual(claimsOf(otherSet.access_token).sub, at.sub,
    "two different usernames must not share a subject.");

  // 5. The session: no second prompt, unless prompt=login asks for one.
  const again = await authorize(meta, params, { cookie: authz.cookie });
  assert.strictEqual(again.prompted, false,
    "a request on an established session should not prompt again.");
  assert.ok(again.params.get("code"),
            "the session request should still issue a code.");
  const forced = await get(meta.authorization_endpoint + "?" +
      form(Object.assign({ prompt: "login" }, params)),
    { headers: { cookie: authz.cookie } });
  assert.strictEqual(forced.status, 302,
    "prompt=login should send the person to the authentication service even " +
        "with a session, got HTTP " + forced.status + ".");
  assert.ok(/\/authn\/login\?authn=/.test(forced.headers.get("location")),
    "and it is the sign-in screen it should send them to, not the client. " +
        "Got: " + forced.headers.get("location"));
  // …and the return URL it stashed must have had `prompt` taken off it, or the
  // person comes back, is sent to sign in again, and never leaves.
  const forcedScreen = await get(meta.issuer + forced.headers.get("location"));
  const forcedId = (await forcedScreen.text())
    .match(/name="authn_id" value="([^"]+)"/)[1];
  const forcedDone = await fetch(meta.issuer + "/authn/login", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ authn_id: forcedId, username: "prompted.user",
                 password: "any-password", action: "login" })
  });
  assert.ok(!/[?&]prompt=/.test(forcedDone.headers.get("location") || ""),
    "the return URL must drop prompt, or signing in loops for ever. Got: " +
        forcedDone.headers.get("location"));
  const silent = await authorize(meta, Object.assign({ prompt: "none" },
      params));
  assert.strictEqual(silent.params.get("error"), "login_required",
    "prompt=none with no session must fail rather than show UI. Got: " +
        silent.params.get("error"));
  log.info("[login] OK — the session skips the prompt, prompt=login forces " +
           "it, prompt=none refuses.");

  // 6. The ways the login screen says no.
  const cancelled = await authorize(meta, params, { action: "cancel" });
  assert.strictEqual(cancelled.params.get("error"), "access_denied",
    "cancelling at the login screen should be access_denied. Got: " +
        cancelled.params.get("error"));
  assert.strictEqual(cancelled.params.get("state"), "login-state",
                     "even the cancel keeps state.");

  const started = await get(meta.authorization_endpoint + "?" + form(params));
  const noName = await get(meta.issuer + started.headers.get("location"));
  const authnId =
      (await noName.text()).match(/name="authn_id" value="([^"]+)"/)[1];
  const blank = await fetch(meta.issuer + "/authn/login", {
    method: "POST", redirect: "manual",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ authn_id: authnId, username: "", password: "x",
               action: "login" })
  });
  assert.strictEqual(blank.status, 200,
      "an empty username should re-show the form, not redirect.");
  assert.ok(/Enter a username/.test(await blank.text()),
            "the form should say what was wrong.");
  const refused = await fetch(meta.issuer + "/authn/login", {
    method: "POST", redirect: "manual",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ authn_id: authnId, username: "carol", password: "invalid",
               action: "login" })
  });
  assert.ok(/Authentication failed for carol/.test(await refused.text()),
    'the reserved password "invalid" should be refused at the sign-in ' +
        'screen too.');
  log.info("[login] OK — cancel, a missing username and the reserved " +
           "password are all handled.");

  // 7. Signing out means the next request prompts again.
  const loggedOut = await get(meta.issuer + "/oauth2/logout",
      { headers: { cookie: authz.cookie } });
  assert.strictEqual(loggedOut.status, 200, "logout should answer.");
  const afterLogout = await get(meta.authorization_endpoint + "?" +
      form(params),
    { headers: { cookie: authz.cookie } });
  assert.strictEqual(afterLogout.status, 302,
    "after signing out the next request should be sent to the " +
        "authentication service again, got HTTP " + afterLogout.status + ".");
  assert.ok(/\/authn\/login\?authn=/.test(afterLogout.headers.get("location")),
    "and that is where it should go — a dropped session means signing in " +
    "again, not a code. Got: " + afterLogout.headers.get("location"));
  log.info("[login] OK — signing out ends the session.");
  log.debug("Leaving testLoginScreen().");
}

// ---------------------------------------------------------------------------
async function testEveryAdvertisedEndpointAnswers(meta) {
  log.debug("Entering testEveryAdvertisedEndpointAnswers().");
  log.info("=== Every advertised endpoint answers ===");
  const simple = ["jwks_uri", "service_documentation", "op_policy_uri",
      "op_tos_uri"];
  for (const member of simple) {
    assert.ok(meta[member], "the metadata should advertise " + member + ".");
    const r = await get(meta[member]);
    assert.strictEqual(r.status, 200, member + " (" + meta[member] +
                       ") returned HTTP " + r.status + ".");
  }
  // The POST endpoints: what matters is that they are implemented, i.e. they do
  // not 404 and they answer in the shape their RFC defines.
  const token = await postForm(meta.token_endpoint,
      { grant_type: "no-such-grant" });
  assert.strictEqual(token.status, 400,
                     "the token endpoint should answer, got HTTP " +
                     token.status + ".");
  assert.strictEqual(token.body.error, "unsupported_grant_type",
    "an unknown grant should be an unsupported_grant_type error. Got: " +
        token.raw);

  const introspect = await postForm(meta.introspection_endpoint, { token: "" });
  assert.strictEqual(introspect.status, 200,
                     "the introspection endpoint should answer 200.");
  assert.strictEqual(introspect.body.active, false,
                     "introspecting nothing should be inactive.");

  const revoke = await postForm(meta.revocation_endpoint,
      { token: "not-a-token" });
  assert.strictEqual(revoke.status, 200,
    "RFC 7009: revoking an invalid token is still a 200. Got HTTP " +
        revoke.status + ".");

  const authz = await authorize(meta, {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        scope: "openid", state: "s0"
  });
  assert.ok(authz.prompted,
      "an unauthenticated authorization request should show the login screen.");
  assert.ok(authz.params.get("code"),
            "the authorization endpoint should issue a code after the login.");
  log.info("[endpoints] OK — authorization, token, jwks, registration, " +
           "introspection, revocation and the " +
           "three document URLs all answer.");
  log.debug("Leaving testEveryAdvertisedEndpointAnswers().");
}

async function testAuthorizationCode(meta, verify) {
  log.debug("Entering testAuthorizationCode().");
  log.info("=== Authorization Code + PKCE ===");
  const verifier = b64u(crypto.randomBytes(32));
  const challenge = b64u(crypto.createHash("sha256").update(verifier,
      "ascii").digest());
  const nonce = "nonce-" + b64u(crypto.randomBytes(6));

  const authz = await authorize(meta, {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid profile email", state: "state-1", nonce: nonce,
    code_challenge: challenge, code_challenge_method: "S256"
  });
  assert.strictEqual(authz.fragment, false,
    "a bare code response must come back in the query, not the fragment.");
  assert.strictEqual(authz.params.get("state"), "state-1",
                     "the authorization response must echo state.");
  assert.strictEqual(authz.params.get("iss"), meta.issuer,
    "the authorization response should identify the issuer (RFC 9207).");
  const code = authz.params.get("code");
  assert.ok(code, "no authorization code came back.");

  // A wrong verifier must be refused before anything is issued.
  const wrong = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: b64u(crypto.randomBytes(32))
  });
  assert.strictEqual(wrong.status, 400, "a bad code_verifier must be refused.");
  assert.strictEqual(wrong.body.error, "invalid_grant",
                     "a bad code_verifier should be invalid_grant.");
  log.info("[code] OK — PKCE is verified, not just accepted.");

  // ... and that refusal must NOT have consumed the code. A check that burns
  // what it refuses answers the next attempt — the corrected one — with
  // "already-used" instead of tokens, which is the wrong sentence at exactly
  // the moment somebody is acting on the right one.
  const corrected = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: verifier
  });
  assert.strictEqual(corrected.status, 200,
    "a refused code_verifier must leave the code redeemable, so the same " +
        "code with the RIGHT verifier should be exchanged. Got HTTP " +
        corrected.status + ": " + corrected.raw);
  log.info("[code] OK — a refused PKCE check does not consume the code.");

  // A fresh one for the token assertions below, so they read against a code
  // whose whole history is this exchange.
  const second = await authorize(meta, {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid profile email", state: "state-2", nonce: nonce,
    code_challenge: challenge, code_challenge_method: "S256"
  });
  const code2 = second.params.get("code");
  const tokens = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code2, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: verifier
  });
  assert.strictEqual(tokens.status, 200, "the code exchange failed: " +
                     tokens.raw);
  const set = tokens.body;
  assert.strictEqual(set.token_type, "Bearer", "token_type should be Bearer.");
  assert.ok(set.expires_in > 0, "expires_in should be positive.");

  const at = verify(set.access_token, "the access token");
  const it = verify(set.id_token, "the ID token");
  const rt = verify(set.refresh_token, "the refresh token");
  assert.strictEqual(at.iss, meta.issuer,
                     "the access token's iss should be the issuer.");
  assert.strictEqual(at.client_id, CLIENT_ID,
                     "the access token should name the client.");
  assert.strictEqual(at.scope, "openid profile email",
                     "the access token should carry the granted scope.");
  assert.ok(at.exp > at.iat,
            "the access token should expire after it was issued.");
  assert.strictEqual(it.aud, CLIENT_ID,
                     "the ID token's audience is the client.");
  assert.strictEqual(it.nonce, nonce,
      "the ID token must echo the nonce from the authorization request.");
  assert.strictEqual(it.at_hash, halfHash(set.access_token),
    "the ID token's at_hash should be the left half of the SHA-256 of the " +
        "access token.");
  assert.strictEqual(it.sub, at.sub,
      "the ID token and access token should describe the same subject.");
  assert.strictEqual(rt.typ, "Refresh",
                     "the refresh token should say what it is.");
  log.info("[code] OK — access / ID / refresh tokens all verify against " +
           "jwks_uri, with matching claims.");

  // Single use, NON-SPEC-ally relaxed to idempotent for the rest of the code's
  // own lifetime: the identical Token Request gets the identical token set
  // back — the first answer, not a second one — because a debugging service
  // that answers a reloaded page with "Unknown or already-used authorization
  // code" has told the user nothing about which of those two it was. The
  // relaxation is the mock's, is documented in docs/mock-sts.md, and RFC 6749
  // section 4.1.2 permits a real server to refuse this outright.
  const replay = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code2, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: verifier
  });
  assert.strictEqual(replay.status, 200,
    "the same Token Request for a code already redeemed should be answered " +
        "with what it was answered the first time. Got HTTP " + replay.status +
        ": " + replay.raw);
  assert.deepStrictEqual(replay.body, set,
    "a replay must return the SAME token set, not a newly minted one — " +
        "nothing is issued twice here.");
  log.info("[code] OK — an identical replay returns the identical tokens.");

  // Everything else about that code is still refused, and the refusal says
  // which part of the request did not match. This is what stops the relaxation
  // from being a way to redeem somebody else's code.
  const otherClient = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code2,
    client_id: CLIENT_ID + "-somebody-else",
    redirect_uri: REDIRECT_URI, code_verifier: verifier
  });
  assert.strictEqual(otherClient.status, 400,
    "a redeemed code presented by a DIFFERENT client must be refused. Got " +
        "HTTP " + otherClient.status + ": " + otherClient.raw);
  assert.strictEqual(otherClient.body.error, "invalid_grant",
                     "that refusal should be invalid_grant.");
  assert.ok(/client_id/.test(String(otherClient.body.error_description)),
    "the refusal should name what differed from the request the code was " +
        "redeemed with. Got: " + otherClient.body.error_description);
  const otherVerifier = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: code2, client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, code_verifier: b64u(crypto.randomBytes(32))
  });
  assert.strictEqual(otherVerifier.status, 400,
    "a redeemed code presented with a different code_verifier must be " +
        "refused. Got HTTP " + otherVerifier.status + ": " +
        otherVerifier.raw);
  assert.ok(/code_verifier/.test(String(otherVerifier.body.error_description)),
    "that refusal should name the code_verifier. Got: " +
        otherVerifier.body.error_description);
  log.info("[code] OK — a redeemed code is replayed only for the request it " +
           "was redeemed with; another client and another verifier are both " +
           "refused, each told what differed.");

  // And a code this server never minted is its own answer, rather than being
  // reported as one that was used: the two are indistinguishable to a client,
  // and only the server can tell them apart.
  const unknown = await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: "not-a-code-" + b64u(
        crypto.randomBytes(12)),
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, code_verifier: verifier
  });
  assert.strictEqual(unknown.status, 400,
    "a code this server never issued must be refused. Got HTTP " +
        unknown.status + ": " + unknown.raw);
  assert.strictEqual(unknown.body.error, "invalid_grant",
                     "an unknown code should be invalid_grant.");
  assert.ok(/memory|restart/i.test(String(unknown.body.error_description)),
    "the refusal for a code that was never issued should say so — this " +
        "server holds codes in memory and cannot know one it never minted. " +
        "Got: " + unknown.body.error_description);
  log.info("[code] OK — an unknown code is reported as unknown, not as used.");
  log.debug("Leaving testAuthorizationCode().");
  return set;
}

async function testAuthorizationErrors(meta) {
  log.debug("Entering testAuthorizationErrors().");
  log.info("=== Authorization endpoint errors ===");
  // No usable redirect_uri: the error cannot be sent to the client, so it is
  // shown to the user agent instead (OAuth 2.0 section 4.1.2.1).
  const r = await get(meta.authorization_endpoint + "?" +
      form({ response_type: "code", client_id: CLIENT_ID }));
  assert.strictEqual(r.status, 400,
      "a request with no redirect_uri must not redirect anywhere.");
  const body = JSON.parse(await r.text());
  assert.strictEqual(body.error, "invalid_request",
                     "the error should be invalid_request. Got: " + body.error);

  // With one, errors go back to the client.
  const unsupported = await authorize(meta, {
    response_type: "cwazy", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        state: "s"
  });
  assert.strictEqual(unsupported.params.get("error"),
                     "unsupported_response_type",
    "an unknown response_type should come back as unsupported_response_type.");
  assert.strictEqual(unsupported.params.get("state"), "s",
                     "an error response must echo state too.");

  const noClient = await authorize(meta, { response_type: "code",
      redirect_uri: REDIRECT_URI });
  assert.strictEqual(noClient.params.get("error"), "invalid_request",
                     "a missing client_id is invalid_request.");
  log.info("[authorize] OK — errors are reported where OAuth 2.0 says they " +
           "should be.");
  log.debug("Leaving testAuthorizationErrors().");
}

async function testImplicitAndHybrid(meta, verify) {
  log.debug("Entering testImplicitAndHybrid().");
  log.info("=== Implicit and hybrid response types ===");
  for (const responseType of ["token", "id_token", "code id_token",
       "code id_token token"]) {
    const authz = await authorize(meta, {
      response_type: responseType, client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
      scope: "openid", nonce: "n-" + responseType.replace(/\s/g, "-"),
          state: "s"
    });
    assert.strictEqual(authz.fragment, true,
      responseType + ": a response carrying a token must use the fragment, " +
          "never the query.");
    const wants = responseType.split(" ");
    if (wants.indexOf("code") >= 0) assert.ok(authz.params.get("code"),
        responseType + ": no code.");
    if (wants.indexOf("token") >= 0) {
      const at = verify(authz.params.get("access_token"), responseType +
          "'s access token");
      assert.strictEqual(at.client_id, CLIENT_ID, responseType +
                         ": the access token should name the client.");
    }
    if (wants.indexOf("id_token") >= 0) {
      const it = verify(authz.params.get("id_token"), responseType +
          "'s ID token");
      assert.strictEqual(it.nonce, "n-" + responseType.replace(/\s/g, "-"),
        responseType + ": the ID token must echo the nonce.");
      if (authz.params.get("access_token")) {
        assert.strictEqual(it.at_hash,
                           halfHash(authz.params.get("access_token")),
          responseType +
              ": at_hash should match the access token in the same response.");
      }
      if (authz.params.get("code")) {
        assert.strictEqual(it.c_hash, halfHash(authz.params.get("code")),
          responseType +
              ": c_hash should match the code in the same response.");
      }
    }
  }
  log.info("[authorize] OK — implicit and hybrid responses are in the " +
           "fragment with matching at_hash / c_hash.");
  log.debug("Leaving testImplicitAndHybrid().");
}

async function testOtherGrants(meta, verify, codeTokens) {
  log.debug("Entering testOtherGrants().");
  log.info("=== The other grants the metadata advertises ===");
  const advertised = meta.grant_types_supported || [];

  const refreshed = await postForm(meta.token_endpoint, {
    grant_type: "refresh_token", refresh_token: codeTokens.refresh_token,
        client_id: CLIENT_ID
  });
  assert.strictEqual(refreshed.status, 200, "the refresh failed: " +
                     refreshed.raw);
  verify(refreshed.body.access_token, "the refreshed access token");
  assert.ok(advertised.indexOf("refresh_token") >= 0,
            "refresh_token should be advertised.");

  const cc = await postForm(meta.token_endpoint,
      { grant_type: "client_credentials", scope: "api" },
    { Authorization: "Basic " +
     Buffer.from("service-client:secret").toString("base64") });
  assert.strictEqual(cc.status, 200, "client_credentials failed: " + cc.raw);
  const ccClaims = verify(cc.body.access_token,
      "the client_credentials access token");
  assert.strictEqual(ccClaims.sub, "service-client",
    "client_credentials should describe the client itself (from " +
        "client_secret_basic).");
  assert.ok(!cc.body.refresh_token,
            "client_credentials has no user, so no refresh token.");
  assert.ok(!cc.body.id_token,
            "client_credentials has no user, so no ID token.");

  const ro = await postForm(meta.token_endpoint, {
    grant_type: "password", username: RO_USER, password: "s3cret",
        scope: "openid", client_id: CLIENT_ID
  });
  assert.strictEqual(ro.status, 200, "the password grant failed: " + ro.raw);
  const roClaims = verify(ro.body.access_token,
      "the password grant access token");
  assert.ok(roClaims.sub.indexOf(RO_USER) !== -1,
            "the password grant should describe the user who authenticated (" +
            RO_USER + "), not " + roClaims.sub + ".");
  verify(ro.body.id_token, "the password grant ID token");

  const roBad = await postForm(meta.token_endpoint, {
    grant_type: "password", username: RO_USER, password: "invalid",
        client_id: CLIENT_ID
  });
  assert.strictEqual(roBad.status, 400,
                     "the reserved 'invalid' password must be refused.");
  assert.strictEqual(roBad.body.error, "invalid_grant",
                     "a failed password grant is invalid_grant.");

  const tx = await postForm(meta.token_endpoint, {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: refreshed.body.access_token,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    audience: "https://api.example.com", client_id: CLIENT_ID
  });
  assert.strictEqual(tx.status, 200, "the token exchange failed: " + tx.raw);
  assert.strictEqual(tx.body.issued_token_type,
                     "urn:ietf:params:oauth:token-type:access_token",
    "RFC 8693: the response must say what kind of token was issued.");
  const txClaims = verify(tx.body.access_token, "the exchanged access token");
  assert.strictEqual(txClaims.aud, "https://api.example.com",
    "the exchanged token should be for the requested audience.");
  assert.strictEqual(txClaims.sub, claimsOf(refreshed.body.access_token).sub,
    "the exchanged token should keep the subject of the token it was " +
        "exchanged for.");

  // Nothing outside the advertised list.
  const unsupported = await postForm(meta.token_endpoint, {
    grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "x"
  });
  assert.strictEqual(unsupported.body.error, "unsupported_grant_type",
    "a grant this server does not implement must be refused.");
  assert.ok(advertised.indexOf(
            "urn:ietf:params:oauth:grant-type:device_code") < 0,
    "the metadata must not advertise a grant the token endpoint refuses.");
  log.info("[grants] OK — " + advertised.length +
           " advertised grants all work, and nothing else does.");
  log.debug("Leaving testOtherGrants().");
}

async function testIntrospectionAndRevocation(meta, verify) {
  log.debug("Entering testIntrospectionAndRevocation().");
  log.info("=== Introspection and revocation ===");
  // A fresh token set, so revoking it cannot disturb the other checks.
  const authz = await authorize(meta, {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        scope: "openid profile"
  });
  const set = (await postForm(meta.token_endpoint, {
    grant_type: "authorization_code", code: authz.params.get("code"),
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI
  })).body;
  const at = verify(set.access_token, "the access token");

  let ins = await postForm(meta.introspection_endpoint,
      { token: set.access_token });
  assert.strictEqual(ins.body.active, true,
                     "a freshly issued token should introspect as active.");
  assert.strictEqual(ins.body.client_id, CLIENT_ID,
                     "introspection should report the client.");
  assert.strictEqual(ins.body.scope, "openid profile",
                     "introspection should report the granted scope.");
  assert.strictEqual(ins.body.sub, at.sub,
                     "introspection should report the subject.");
  assert.strictEqual(ins.body.jti, at.jti,
                     "introspection should report the token identifier.");
  assert.strictEqual(ins.body.token_type, "Bearer",
                     "an access token introspects as a Bearer token.");

  ins = await postForm(meta.introspection_endpoint,
      { token: set.refresh_token });
  assert.strictEqual(ins.body.active, true,
                     "the refresh token should introspect as active.");
  assert.strictEqual(ins.body.token_type, "refresh_token",
    "introspection should distinguish a refresh token. Got: " +
        ins.body.token_type);

  // A token this server did not sign must not introspect as active, however
  // well-formed it looks.
  const forged = ["e30", b64u(JSON.stringify({ sub: "attacker",
      exp: 4102444800 })), "not-a-signature"].join(".");
  ins = await postForm(meta.introspection_endpoint, { token: forged });
  assert.strictEqual(ins.body.active, false,
                     "a forged token must introspect as INACTIVE.");
  log.info("[introspect] OK — real tokens report their claims, forged ones " +
           "are inactive.");

  assert.strictEqual((await postForm(meta.revocation_endpoint,
                     { token: set.access_token })).status, 200,
    "revocation should answer 200.");
  ins = await postForm(meta.introspection_endpoint,
      { token: set.access_token });
  assert.strictEqual(ins.body.active, false,
                     "a revoked access token must stop being active.");

  await postForm(meta.revocation_endpoint, { token: set.refresh_token });
  const afterRevoke = await postForm(meta.token_endpoint, {
    grant_type: "refresh_token", refresh_token: set.refresh_token,
        client_id: CLIENT_ID
  });
  assert.strictEqual(afterRevoke.status, 400,
                     "a revoked refresh token must not mint new tokens.");
  assert.strictEqual(afterRevoke.body.error, "invalid_grant",
                     "using a revoked refresh token is invalid_grant.");
  log.info("[revoke] OK — revocation takes effect for both introspection " +
           "and refresh.");
  log.debug("Leaving testIntrospectionAndRevocation().");
}

async function testRegistration(meta) {
  log.debug("Entering testRegistration().");
  log.info("=== Dynamic client registration (RFC 7591 / 7592) ===");
  const r = await fetch(meta.registration_endpoint, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Endpoint Test Client",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "client_secret_basic"
    })
  });
  assert.strictEqual(r.status, 201,
                     "registration should answer 201 Created, got " + r.status +
                     ".");
  const reg = await r.json();
  assert.ok(reg.client_id, "registration must return a client_id.");
  assert.ok(reg.client_secret, "registration should return a client_secret.");
  assert.ok(reg.client_id_issued_at > 0,
            "registration should say when the client was issued.");
  assert.strictEqual(reg.client_secret_expires_at, 0,
                     "0 means the secret does not expire.");
  assert.strictEqual(reg.client_name, "Endpoint Test Client",
                     "the registration should echo the metadata.");
  assert.ok(reg.registration_access_token && reg.registration_client_uri,
    "RFC 7592 management needs a registration access token and URI.");

  const authed = { Authorization: "Bearer " + reg.registration_access_token };
  const read = await fetch(reg.registration_client_uri, { headers: authed });
  assert.strictEqual(read.status, 200, "reading the registration failed.");
  assert.strictEqual((await read.json()).client_id, reg.client_id,
                     "the read should return the same client.");

  const unauth = await fetch(reg.registration_client_uri);
  assert.strictEqual(unauth.status, 401,
      "reading without the registration access token must be refused.");

  const updated = await fetch(reg.registration_client_uri, {
    method: "PUT",
        headers: Object.assign({ "Content-Type": "application/json" }, authed),
    body: JSON.stringify({ client_name: "Renamed Client",
                         redirect_uris: [REDIRECT_URI] })
  });
  assert.strictEqual(updated.status, 200, "updating the registration failed.");
  const after = await updated.json();
  assert.strictEqual(after.client_name, "Renamed Client",
                     "the update should take.");
  assert.strictEqual(after.client_id, reg.client_id,
                     "an update must not change the client_id.");

  const deleted = await fetch(reg.registration_client_uri, { method: "DELETE",
      headers: authed });
  assert.strictEqual(deleted.status, 204,
                     "deleting the registration should answer 204.");
  const gone = await fetch(reg.registration_client_uri, { headers: authed });
  assert.strictEqual(gone.status, 404,
                     "the client should be gone after a delete.");
  log.info("[register] OK — register, read, update and delete, with the " +
           "management calls protected.");
  log.debug("Leaving testRegistration().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. metadata=" + metadataUrl);
  const metaResponse = await get(metadataUrl);
  assert.strictEqual(metaResponse.status, 200,
                     "the metadata document is not available: HTTP " +
                     metaResponse.status);
  const meta = JSON.parse(await metaResponse.text());
  const jwks = await (await get(meta.jwks_uri)).json();
  assert.ok(jwks.keys && jwks.keys.length, "jwks_uri returned no keys.");
  const verify = makeVerifier(jwks);

  await testEveryAdvertisedEndpointAnswers(meta);
  await testLoginScreen(meta, verify);
  await testAuthorizationErrors(meta);
  const codeTokens = await testAuthorizationCode(meta, verify);
  await testImplicitAndHybrid(meta, verify);
  await testOtherGrants(meta, verify, codeTokens);
  await testIntrospectionAndRevocation(meta, verify);
  await testRegistration(meta);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option('-u, --url <url>',
                  'ignored; kept for a uniform CLI across the suite'));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
