// File: rfc9700.js
//
// ---------------------------------------------------------------------------
// RFC 9700 (OAuth 2.0 Security Best Current Practice) — the CLIENT half.
//
// The mock STS grew an `oauth2_bcp.js` that holds the same specification from
// the authorization server's side. This is its counterpart: what RFC 9700 asks
// of a CLIENT, expressed once, so that the two pages of the OAuth2 / OIDC
// workflow enforce the same rules and say the same thing about them.
//
// **It is off by default and it has to be.** A debugger exists to be pointed at
// identity providers that are wrong — that is most of what anybody uses it for.
// An implicit response with no state on it is a finding worth SEEING, and a
// debugger that refuses to send the request cannot show it to you. So every
// rule below is gated behind one switch (the RFC 9700 checkbox in the
// Configuration Parameters pane), and with the switch off this module is not
// consulted at all: `enabled()` is false, no check runs, no pane is drawn, and
// both pages behave exactly as they did before this file existed. That
// mode-off contract is the thing to protect when changing anything here —
// tests/rfc9700_client.js asserts it, because it is invisible from inside a
// single run.
//
// **What is NOT gated, and why.** Four of the fifteen sections ask something of
// the client's own posture rather than of its conversation with an identity
// provider: the callback must not be an open redirector (11), the redirect it
// does make should be 303 rather than 307 (12), the pages must refuse framing
// (14), and any browser messaging must match origins exactly (15). None of
// those can break a flow against a non-compliant provider, because none of them
// is visible to the provider. They are therefore always in force, in
// client/server.js and in the pages themselves, and appear here as rows with
// `enforced: "always"` so the report says what is true rather than only what
// this switch turned on.
//
// **The catalogue is the interface.** Every row carries the section from the
// checklist this project is working to (see rcbj/mock-sts issue #2), the level
// RFC 9700 states it at, and how this client answers it. Add a check and you
// add a row; the report, the tests and the documentation all read the rows
// rather than keeping lists of their own. A check with no row is invisible to
// all three.
//
// **No DOM, and storage is optional.** Both pages call in with facts and get
// findings back — this module never reads a field or writes a pane, which is
// what lets tests/rfc9700_client.js load it in node and drive every rule
// without a browser. The one piece of state it does own is the TRANSACTION
// record (section 2), and that lives in sessionStorage rather than
// localStorage deliberately: RFC 9700 section 2.1 asks that the PKCE and nonce
// values be bound to the USER-AGENT transaction, and localStorage is shared by
// every tab and outlives the browsing session, which is the opposite of that.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "rfc9700",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      // A missing log level must not stop the module loading.
      return "info";
    }
  })()
});

// The localStorage key the checkbox on both pages writes. It is a
// configuration setting like every other field in that pane, so it lives where
// the rest of them live and survives a page load; the TRANSACTION state below
// deliberately does not.
var MODE_KEY = "rfc9700_mode";

// Where one authorization transaction is remembered. sessionStorage, per the
// note at the top: section 2.1's "bound to the user-agent transaction".
var TRANSACTION_KEY = "rfc9700_transaction";

// Authorization codes this client has already redeemed, and refresh tokens it
// has already spent. Both are single-use by RFC 9700 (sections 3 and 9) and
// both are the client's own obligation, not something the server can be
// trusted to enforce for us — the whole point of the rule is what happens when
// a server does NOT.
var SPENT_KEY = "rfc9700_spent";

// The three levels a finding can carry, and what each does in mode:
//
//   must   — the flow STOPS. RFC 9700 states it as MUST or MUST NOT and the
//            client is the party that can honour it.
//   should — the flow continues and the report says so. RFC 9700 states it as
//            SHOULD, or the client can only observe rather than enforce.
//   info   — something worth reporting that is not a failing: what the server
//            advertised, what was detected, what was checked and passed.
//
// A level is not decoration. `must` is the set of things that can refuse a
// request somebody typed, so a row promoted to `must` by mistake looks exactly
// like the debugger being broken.
var MUST = "must";
var SHOULD = "should";
var INFO = "info";


// ---------------------------------------------------------------------------
// The catalogue.
//
// `section` is the section number from the fifteen-section checklist this work
// follows. `level` is what RFC 9700 states. `enforced` is what THIS client
// does, and is one of:
//
//   enforced  — checked in mode, and a `must` failure refuses.
//   detected  — checked in mode and reported; the client cannot enforce it,
//               either because the obligation is the server's or because all
//               the client can do is observe what came back.
//   always    — in force whether or not the mode is on, because honouring it
//               cannot break a flow against a non-compliant provider. These
//               live outside this module (client/server.js's headers and its
//               callback, and the pages' own absence of framing and of
//               postMessage); the row exists so the report is complete.
//   no        — deliberately not done, with the reason in `note`. A row here is
//               worth more than a silent omission.
// ---------------------------------------------------------------------------
var REQUIREMENTS = [
  // -- 1. Authorization Flow -------------------------------------------------
  { id: "1.1", section: 1, level: "MUST", enforced: "enforced",
    title: "redirect_uri is an exact absolute URI",
    note: "A wildcard, a bare path, or a value with a fragment is refused " +
          "before the browser leaves the page. Exact string matching is the " +
          "server's job, but a client that sends a pattern has already made " +
          "it impossible." },
  { id: "1.2", section: 1, level: "MUST NOT", enforced: "enforced",
    title: "no wildcard or pattern redirect_uri",
    note: "A '*' anywhere in the value is refused." },
  { id: "1.3", section: 1, level: "MUST", enforced: "enforced",
    title: "redirect_uri is https, or loopback",
    note: "RFC 8252's loopback exception is honoured: 127.0.0.1, [::1] and " +
          "localhost may be http and may use any port. That exception is " +
          "load-bearing here rather than theoretical — the debugger's own " +
          "callback is http://localhost:3000/callback, so without it this " +
          "mode could not be used against a local stack at all." },
  { id: "1.4", section: 1, level: "MUST", enforced: "enforced",
    title: "the authorization endpoint is https, or loopback",
    note: "An authorization response MUST NOT travel over an unencrypted " +
          "connection, and the response comes back from wherever the request " +
          "went." },
  { id: "1.5", section: 1, level: "MUST", enforced: "always",
    title: "the client's redirect endpoint is not an open redirector",
    note: "GET/POST /callback in client/server.js forwards only to this " +
          "deployment's own configured uiUrl — every Location it sends " +
          "BEGINS with debuggerLandingUrl(), so nothing on the request can " +
          "decide the origin or the path. It does copy the response's " +
          "parameters through after the '?' or the '#', which is data on a " +
          "URL whose destination is fixed and is not a redirect anywhere; " +
          "the distinction is worth keeping straight, because the crude " +
          "version of this rule would forbid forwarding the authorization " +
          "response at all. Asserted by tests/rfc9700_client.js over the " +
          "source and by tests/rfc9700_flows.js over the running " +
          "deployment, because the failure is one edit away and silent." },
  { id: "1.6", section: 1, level: "MUST", enforced: "enforced",
    title: "PKCE is used",
    note: "MUST for a public client (no client secret), SHOULD for a " +
          "confidential one. In mode the switch is forced on and the 'no' " +
          "option is disabled, so the level is met either way." },
  { id: "1.7", section: 1, level: "SHOULD", enforced: "enforced",
    title: "the PKCE method is S256",
    note: "'plain' is refused. This client only ever generated S256, so the " +
          "check exists to keep that true rather than to fix it." },
  { id: "1.8", section: 1, level: "MUST", enforced: "enforced",
    title: "code_challenge and nonce are transaction-specific",
    note: "state, nonce and the PKCE verifier are regenerated on every " +
          "authorization request in mode, rather than being reused from the " +
          "stored configuration. Reuse is what makes a captured value worth " +
          "capturing." },
  { id: "1.9", section: 1, level: "MUST", enforced: "enforced",
    title: "the transaction is bound to the user agent",
    note: "The issuer, state, nonce and code_verifier are written to " +
          "sessionStorage, which is per-tab and dies with the browsing " +
          "session. localStorage — where this workflow keeps its " +
          "configuration — is neither." },
  { id: "1.10", section: 1, level: "SHOULD", enforced: "detected",
    title: "the server advertises PKCE support",
    note: "code_challenge_methods_supported is read from the metadata. Its " +
          "absence is reported rather than fatal: it is exactly the " +
          "condition under which RFC 9700 says PKCE MUST NOT be relied on " +
          "for CSRF protection, which is why 2.1 requires state as well." },
  { id: "1.11", section: 1, level: "SHOULD NOT", enforced: "enforced",
    title: "no Implicit Grant, and no response type returning an access " +
           "token from the authorization endpoint",
    note: "In mode the grant selector disables OAuth2 Implicit, both OIDC " +
          "Implicit flows, and the two Hybrid flows that carry 'token'. " +
          "OIDC Hybrid (code id_token) survives: it returns no access token " +
          "from the authorization endpoint, and its id_token is the code " +
          "injection defence section 3 asks for." },
  { id: "1.12", section: 1, level: "SHOULD", enforced: "enforced",
    title: "response_type=code is preferred",
    note: "What 1.11 leaves standing, and the reason it is stated as its own " +
          "row: 1.11 says which response types are refused, and a client " +
          "can satisfy that and still ask for something odd. This is the " +
          "positive form — the request carries a code and the token comes " +
          "from a back-channel call the browser's history never sees." },

  // -- 2. CSRF and Mix-Up Protection ----------------------------------------
  { id: "2.1", section: 2, level: "MUST", enforced: "enforced",
    title: "a one-time state value is sent",
    note: "Required in mode even when PKCE is in use: PKCE may be relied on " +
          "for CSRF only after verifying the server supports it, and 1.10 " +
          "cannot always verify that." },
  { id: "2.2", section: 2, level: "MUST", enforced: "enforced",
    title: "a returned state that does not match REFUSES the response",
    note: "This is the rule that changes most. Outside mode the page prints " +
          "a State Report and carries on to the token request; in mode a " +
          "mismatch stops the flow, because a report nobody reads is not a " +
          "CSRF defence." },
  { id: "2.3", section: 2, level: "MUST", enforced: "enforced",
    title: "state is single-use",
    note: "Consumed when the authorization response is processed. A second " +
          "load of the same callback URL — a refresh, or a back button — no " +
          "longer matches, which is what 'one-time' means." },
  { id: "2.4", section: 2, level: "MUST", enforced: "enforced",
    title: "the issuer is stored with the authorization request and bound " +
           "to the session",
    note: "Section 2's mix-up defence. The issuer that was current when the " +
          "request was built is written onto the transaction record, so the " +
          "response is judged against the server it was actually sent to and " +
          "not against whatever the configuration says now." },
  { id: "2.5", section: 2, level: "MUST", enforced: "enforced",
    title: "the RFC 9207 iss parameter is checked when present",
    note: "A returned iss that does not match the stored issuer refuses the " +
          "response. This is the mechanism RFC 9700 prefers over distinct " +
          "redirect URIs." },
  { id: "2.6", section: 2, level: "MUST", enforced: "enforced",
    title: "iss is REQUIRED when the server advertises it",
    note: "authorization_response_iss_parameter_supported: true and no iss " +
          "on the response is a refusal — the advertisement is what makes " +
          "its absence meaningful rather than merely old." },
  { id: "2.7", section: 2, level: "MUST", enforced: "enforced",
    title: "the ID Token's iss claim matches the stored issuer",
    note: "The OIDC form of the same check, and the one that still works " +
          "when the server publishes no iss parameter." },

  // -- 3. Authorization Code Protection -------------------------------------
  { id: "3.1", section: 3, level: "MUST", enforced: "enforced",
    title: "an authorization code is redeemed at most once",
    note: "Invalidating a used code is the server's obligation; not " +
          "presenting one twice is the client's, and it is the client that " +
          "can be made to by a page reload." },
  { id: "3.2", section: 3, level: "MUST", enforced: "enforced",
    title: "the ID Token's nonce is validated, and NO TOKEN IS USED until " +
           "it does",
    note: "The code-injection defence. Outside mode this workflow does not " +
          "validate nonce at all — it decodes it for display and for " +
          "grouping the Token History. In mode a mismatch discards the whole " +
          "token set: nothing reaches Token History, the UserInfo links, or " +
          "the refresh pane." },
  { id: "3.3", section: 3, level: "MUST", enforced: "enforced",
    title: "a nonce is sent on every authentication request",
    note: "Nothing to validate otherwise. Regenerated per transaction by " +
          "1.8." },

  // -- 4. Access Token Protection -------------------------------------------
  { id: "4.1", section: 4, level: "SHOULD", enforced: "enforced",
    title: "the access token is sender-constrained",
    note: "In mode the DPoP switch on this workflow defaults ON. It stays a " +
          "switch rather than becoming compulsory, because RFC 9700 states " +
          "this at SHOULD and because a provider that ignores a proof and " +
          "answers Bearer is a finding this debugger exists to show. Turning " +
          "it off in mode produces a SHOULD row rather than a refusal." },
  { id: "4.2", section: 4, level: "SHOULD", enforced: "detected",
    title: "the token is audience-restricted",
    note: "The RFC 8707 resource indicator is sent when the Resource field " +
          "is filled in, and the returned token's aud is reported. A token " +
          "with no aud, or one naming more than a small set, is a SHOULD " +
          "row." },
  { id: "4.3", section: 4, level: "SHOULD", enforced: "detected",
    title: "least privilege — scope is minimal",
    note: "What was asked for and what was granted are compared. A grant " +
          "wider than the request is reported; so is a request with no scope " +
          "at all, which on many servers means 'everything this client has'." },
  { id: "4.4", section: 4, level: "MUST NOT", enforced: "always",
    title: "no access token in a URI query parameter",
    note: "Every protected call this workflow makes carries the token in an " +
          "Authorization header or a POST body. Asserted over the source by " +
          "tests/rfc9700_client.js, because it is a property of every call " +
          "site rather than of one function." },
  { id: "4.5", section: 4, level: "MUST", enforced: "detected",
    title: "the proof of possession is validated by the resource server",
    note: "Not the client's obligation, and not something a client can " +
          "check. Reported as the server-side half so the report is not " +
          "read as a complete account of section 4." },
  { id: "4.6", section: 4, level: "MUST", enforced: "detected",
    title: "replay of the proof is prevented",
    note: "As 4.5. The mock STS's own RFC 9700 mode covers both, and " +
          "tests/sts_dpop.js is where they are actually exercised." },

  // -- 5. Resource Owner Password Credentials -------------------------------
  { id: "5.1", section: 5, level: "MUST NOT", enforced: "enforced",
    title: "the Resource Owner Password Credentials grant is not used",
    note: "Disabled in the grant selector on both pages in mode, and refused " +
          "at the token request if it is reached by some other route — a " +
          "stored configuration, or a hand-edited form. Two places rather " +
          "than one because the selector is a control and the token request " +
          "is the act." },

  // -- 6. Client Authentication ---------------------------------------------
  { id: "6.1", section: 6, level: "RECOMMENDED", enforced: "detected",
    title: "asymmetric client authentication is preferred",
    note: "When the server advertises private_key_jwt or tls_client_auth in " +
          "token_endpoint_auth_methods_supported and this client is " +
          "configured with a shared secret, a SHOULD row says so. This " +
          "workflow implements client_secret_basic and client_secret_post " +
          "only — see the deliberate gap noted under 6.3." },
  { id: "6.2", section: 6, level: "MUST NOT", enforced: "enforced",
    title: "the client secret never travels in a query parameter",
    note: "The token, revocation and introspection calls put it in the " +
          "Authorization header or the POST body. In mode the header style " +
          "is selected by default, which is client_secret_basic." },
  { id: "6.3", section: 6, level: "RECOMMENDED", enforced: "no",
    title: "private_key_jwt / mutual-TLS client authentication",
    note: "NOT IMPLEMENTED in this workflow. It is a credential mechanism " +
          "rather than a check — a key pair pane, an assertion signed in " +
          "the browser, and a third auth style threaded through " +
          "common/data.js and the api's proxy — so it is a piece of work " +
          "rather than a rule, and inventing a half of it would be worse " +
          "than a row that says so. The mock STS accepts all six methods " +
          "already, so the server side is not what is missing." },

  // -- 7. Authorization Server Metadata -------------------------------------
  { id: "7.1", section: 7, level: "SHOULD", enforced: "enforced",
    title: "the client consumes the server's metadata",
    note: "In mode the endpoints must have been populated from a discovery " +
          "or RFC 8414 document rather than typed. Hand-typed endpoints are " +
          "the misconfiguration this section exists to remove, and they are " +
          "also how somebody points the debugger at half of one server and " +
          "half of another." },
  { id: "7.2", section: 7, level: "MUST", enforced: "enforced",
    title: "the issuer matches the document it came from",
    note: "RFC 8414 section 3.3 / OIDC Discovery: the issuer identifier must " +
          "be the metadata URL with the well-known path removed. A document " +
          "claiming to speak for somebody else is the mix-up attack in its " +
          "simplest form." },
  { id: "7.3", section: 7, level: "SHOULD", enforced: "detected",
    title: "code_challenge_methods_supported advertises S256",
    note: "The same fact 1.10 reads, reported here as a property of the " +
          "metadata rather than of the request." },
  { id: "7.4", section: 7, level: "SHOULD", enforced: "detected",
    title: "the chosen response_type and grant type are advertised",
    note: "Compared against response_types_supported and " +
          "grant_types_supported. A response type the server never claimed " +
          "is not an error a client can fix, but it is the first thing to " +
          "know when the response is not what was expected." },

  // -- 8. TLS ---------------------------------------------------------------
  { id: "8.1", section: 8, level: "MUST", enforced: "enforced",
    title: "every configured endpoint is https, or loopback",
    note: "Authorization, token, userinfo, jwks, registration, revocation, " +
          "introspection, device authorization and end-session alike. One " +
          "http endpoint among nine https ones is the interesting case, and " +
          "it is the one a per-call check would miss." },
  { id: "8.2", section: 8, level: "MUST", enforced: "enforced",
    title: "certificate validation is not disabled",
    note: "This workflow has an SSL Validate switch for testing against " +
          "self-signed certificates. In mode it is forced on: an " +
          "unauthenticated TLS connection is not the 'use TLS' this section " +
          "asks for." },
  { id: "8.3", section: 8, level: "MUST", enforced: "detected",
    title: "a terminating proxy protects the connection behind it and " +
           "sanitizes inbound security headers",
    note: "A deployment property, not a client one. Reported so section 8 " +
          "is not read as fully covered by 8.1 and 8.2." },

  // -- 9. Refresh Tokens ----------------------------------------------------
  { id: "9.1", section: 9, level: "MUST", enforced: "enforced",
    title: "a rotated refresh token replaces the old one, which is never " +
           "sent again",
    note: "The client's half of rotation. The previous token is marked spent " +
          "the moment a refresh response carries a new one, and presenting a " +
          "spent token is refused here rather than being left for the server " +
          "to answer — a server that answers it is precisely the situation " +
          "worth seeing." },
  { id: "9.2", section: 9, level: "MUST", enforced: "detected",
    title: "a public client's refresh token is rotated or sender-constrained",
    note: "Detected across a refresh: whether the response carried a new " +
          "refresh token, and whether the token is DPoP-bound. Neither is " +
          "something a client can impose." },
  { id: "9.3", section: 9, level: "MUST", enforced: "always",
    title: "the refresh token never travels in a URL",
    note: "It goes in the POST body of the refresh and revocation calls. " +
          "Asserted over the source with 4.4." },
  { id: "9.4", section: 9, level: "SHOULD", enforced: "detected",
    title: "refresh tokens expire after a period of inactivity",
    note: "The server's decision. Reported when a refresh is refused with " +
          "invalid_grant, which is what an expired one looks like from " +
          "here." },

  // -- 10. Prevent Token Leakage --------------------------------------------
  { id: "10.1", section: 10, level: "MUST NOT", enforced: "enforced",
    title: "the authorization response is scrubbed from the address bar " +
           "and from history",
    note: "history.replaceState removes code, state, iss and any token from " +
          "the URL as soon as the response has been read. Outside mode the " +
          "URL is left alone, because a debugger's user frequently wants to " +
          "copy it." },
  { id: "10.2", section: 10, level: "SHOULD", enforced: "always",
    title: "Referrer-Policy: no-referrer",
    note: "Sent as a header by client/server.js and carried as a meta " +
          "element in the pages, so it holds on the deployed static sites " +
          "too, which have no server of ours in front of them." },
  { id: "10.3", section: 10, level: "SHOULD", enforced: "always",
    title: "no third-party resource or external link on a page that " +
           "receives an authorization response",
    note: "Every script, stylesheet and image on this workflow's two pages " +
          "is same-origin — there is no third-party RESOURCE to carry a " +
          "referrer. There are two external LINKS (the privacy note and the " +
          "footer), which is the half of this rule not fully met: they are " +
          "rel=\"noopener noreferrer\" and 10.2 suppresses the Referer " +
          "header for everything on the page, so nothing leaks, but RFC " +
          "9700 asks for their absence rather than their neutralisation. " +
          "tests/rfc9700_client.js asserts the resource half and pins the " +
          "link half so it cannot grow." },
  { id: "10.4", section: 10, level: "SHOULD", enforced: "enforced",
    title: "form_post response mode is used when the server offers it",
    note: "The authorization response arrives in a POST body instead of a " +
          "query string, so it is never in the address bar at all. Sent when " +
          "the metadata advertises form_post in response_modes_supported " +
          "AND this build has a backend to receive the POST — a static " +
          "deployment has no /callback of ours, so asking for form_post " +
          "there would produce a response nothing can read." },
  { id: "10.5", section: 10, level: "SHOULD", enforced: "enforced",
    title: "an authorization code rather than a token comes back from the " +
           "authorization endpoint",
    note: "The same rule 1.11 enforces, listed again because this section " +
          "states it for a different reason: what is in the URL is in the " +
          "history." },
  { id: "10.6", section: 10, level: "MUST", enforced: "detected",
    title: "a resource server treats the access token as a secret",
    note: "Not this client's obligation. Listed so the section is not read " +
          "as complete." },

  // -- 11. Open Redirectors -------------------------------------------------
  { id: "11.1", section: 11, level: "MUST NOT", enforced: "always",
    title: "this client exposes no open redirector",
    note: "The same property 1.5 names, which is where it is checked. It is " +
          "stated in both sections of RFC 9700 and so is stated in both " +
          "here." },
  { id: "11.2", section: 11, level: "MUST NOT", enforced: "detected",
    title: "the server did not redirect for an invalid client_id or " +
           "redirect_uri",
    note: "Observable only: an error delivered TO the redirect_uri when the " +
          "request named an unknown client is the shape this forbids, and it " +
          "is reported as such." },

  // -- 12. HTTP 307 Redirects -----------------------------------------------
  { id: "12.1", section: 12, level: "SHOULD", enforced: "always",
    title: "this client's own redirect after a POST is 303",
    note: "POST /callback answers 303. A 307 would replay the method and the " +
          "body — which on a form_post authorization response is the " +
          "response itself — onto the next hop." },
  { id: "12.2", section: 12, level: "MUST NOT", enforced: "detected",
    title: "the server did not use 307 for a credential-bearing redirect",
    note: "A browser follows a redirect before any script here runs, so this " +
          "cannot be observed from the page. It is the mock STS's own rule " +
          "(its authentication service answers 303) and it is exercised " +
          "there." },

  // -- 13. Client / Resource-Owner Identity Separation ----------------------
  { id: "13.1", section: 13, level: "SHOULD NOT", enforced: "detected",
    title: "the subject of a user token is not confusable with the client id",
    note: "A token from a user-facing grant whose sub equals the client_id " +
          "is reported. That is the collision this section is about, and " +
          "from the client's side it is the only part of it that is " +
          "visible." },

  // -- 14. Clickjacking -----------------------------------------------------
  { id: "14.1", section: 14, level: "MUST", enforced: "always",
    title: "the debugger's own pages refuse to be framed",
    note: "client/server.js sends Content-Security-Policy: frame-ancestors " +
          "'none' and X-Frame-Options: DENY on every page. CSP Level 2 is " +
          "what RFC 9700 asks for; X-Frame-Options is there for what does " +
          "not implement it." },
  { id: "14.2", section: 14, level: "MUST", enforced: "always",
    title: "the debugger never frames an authorization endpoint",
    note: "It navigates to it. There is no iframe anywhere in client/public " +
          "or client/src, and tests/rfc9700_client.js keeps it that way — a " +
          "client that framed a sign-in page would be teaching the habit " +
          "this section forbids." },

  // -- 15. Browser postMessage / In-Browser Communication -------------------
  { id: "15.1", section: 15, level: "MUST", enforced: "always",
    title: "the OAuth2 / OIDC workflow uses no browser messaging at all",
    note: "There is no postMessage and no message listener on either page or " +
          "in anything they bundle, so none of this section's failure modes " +
          "is reachable. That is the compliant answer rather than an " +
          "omission, and it is asserted rather than assumed." },
  { id: "15.2", section: 15, level: "MUST NOT", enforced: "always",
    title: "no '*' target origin anywhere in the client",
    note: "The one postMessage in this tree is the WebAuthn analyzer's " +
          "bridge to the browser extension, and it targets " +
          "window.location.origin." },
  { id: "15.3", section: 15, level: "MUST", enforced: "always",
    title: "every message listener exact-matches the sender origin",
    note: "That same bridge compares event.origin against " +
          "window.location.origin as well as event.source against window. " +
          "Source alone is not an origin check." }
];


// ---------------------------------------------------------------------------
// Storage. Guarded rather than assumed, so this module loads in node.
//
// A node caller gets a plain object standing in for each store. That is enough
// for the tests, which drive one transaction at a time, and it means no check
// in here has to know whether it is in a browser.
// ---------------------------------------------------------------------------
var memoryLocal = {};
var memorySession = {};

function localStore() {
  log.debug("Entering localStore().");
  try {
    if (typeof localStorage !== "undefined" && localStorage) {
      log.debug("Leaving localStore(). Real localStorage.");
      return localStorage;
    }
  } catch (e) {
    // Access to localStorage throws in some sandboxes (a file: origin, a
    // blocked third-party context). Falling back keeps the module usable
    // rather than taking the page down with it.
    log.debug("localStorage is not reachable: " + e.message);
  }
  log.debug("Leaving localStore(). In-memory stand-in.");
  return {
    getItem: function (k) {
      return (k in memoryLocal) ? memoryLocal[k] : null;
    },
    setItem: function (k, v) { memoryLocal[k] = String(v); },
    removeItem: function (k) { delete memoryLocal[k]; }
  };
}

function sessionStore() {
  log.debug("Entering sessionStore().");
  try {
    if (typeof sessionStorage !== "undefined" && sessionStorage) {
      log.debug("Leaving sessionStore(). Real sessionStorage.");
      return sessionStorage;
    }
  } catch (e) {
    // As localStore(): reachability is not guaranteed and must not be fatal.
    log.debug("sessionStorage is not reachable: " + e.message);
  }
  log.debug("Leaving sessionStore(). In-memory stand-in.");
  return {
    getItem: function (k) {
      return (k in memorySession) ? memorySession[k] : null;
    },
    setItem: function (k, v) { memorySession[k] = String(v); },
    removeItem: function (k) { delete memorySession[k]; }
  };
}


// ---------------------------------------------------------------------------
// The mode switch.
// ---------------------------------------------------------------------------

// True when the RFC 9700 checkbox is ticked. Everything in this file is
// downstream of this one answer, and it is deliberately a strict comparison
// against the string "true": an unreadable or absent value means OFF, which is
// the direction that leaves the debugger able to talk to a broken provider.
function enabled() {
  log.debug("Entering enabled().");
  var value = localStore().getItem(MODE_KEY);
  log.debug("Leaving enabled(). value=" + value);
  return value === "true";
}

function setEnabled(on) {
  log.debug("Entering setEnabled(). on=" + on);
  localStore().setItem(MODE_KEY, on ? "true" : "false");
  log.debug("Leaving setEnabled().");
}


// ---------------------------------------------------------------------------
// URL rules, shared by sections 1 and 8.
// ---------------------------------------------------------------------------

// RFC 8252 section 7.3's loopback interface, plus the name that resolves to it.
// The specification prefers the IP literals and says so; `localhost` is
// included because it is what this project's own stacks use everywhere and
// refusing it would make the mode untestable rather than stricter.
function isLoopbackHost(hostname) {
  log.debug("Entering isLoopbackHost(). hostname=" + hostname);
  var host = String(hostname || "").toLowerCase();
  var loopback = host === "127.0.0.1" || host === "::1" || host === "[::1]" ||
      host === "localhost" || /^127\./.test(host);
  log.debug("Leaving isLoopbackHost(). loopback=" + loopback);
  return loopback;
}

// Parse without throwing. Callers here always want to say something specific
// about an unusable value rather than propagate a TypeError into a click
// handler.
function parseUrl(value) {
  log.debug("Entering parseUrl().");
  if (typeof value !== "string" || value.trim() === "") {
    log.debug("Leaving parseUrl(). Empty.");
    return null;
  }
  try {
    var parsed = new URL(value.trim());
    log.debug("Leaving parseUrl(). Parsed.");
    return parsed;
  } catch (e) {
    // Not an absolute URL. Every field this is applied to is meant to hold
    // one, so the caller reports it rather than trying a base.
    log.debug("Leaving parseUrl(). Unparseable.");
    return null;
  }
}

// Section 8.1 for one endpoint: https, or http on the loopback interface.
// Returns null when it is fine and a sentence when it is not, because every
// caller wants the sentence rather than a boolean it would then have to
// compose one from.
function tlsProblem(label, value) {
  log.debug("Entering tlsProblem(). label=" + label);
  if (!value) {
    log.debug("Leaving tlsProblem(). Not configured.");
    return null;
  }
  var parsed = parseUrl(value);
  if (!parsed) {
    log.debug("Leaving tlsProblem(). Unparseable.");
    return label + " is not an absolute URL: " + value;
  }
  if (parsed.protocol === "https:") {
    log.debug("Leaving tlsProblem(). https.");
    return null;
  }
  if (parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)) {
    log.debug("Leaving tlsProblem(). http on loopback, allowed.");
    return null;
  }
  log.debug("Leaving tlsProblem(). Refused.");
  return label + " must be https (or http on the loopback interface); it is " +
      parsed.protocol + "//" + parsed.host;
}


// ---------------------------------------------------------------------------
// Findings.
//
// A finding names the requirement it comes from, so the report can link a
// sentence back to a row and a reader can tell an opinion from a citation.
// ---------------------------------------------------------------------------
function finding(id, level, message) {
  log.debug("Entering finding(). id=" + id);
  var row = requirement(id);
  log.debug("Leaving finding().");
  return {
    id: id,
    section: row ? row.section : null,
    level: level,
    title: row ? row.title : id,
    message: message
  };
}

function requirement(id) {
  log.debug("Entering requirement(). id=" + id);
  for (var i = 0; i < REQUIREMENTS.length; i++) {
    if (REQUIREMENTS[i].id === id) {
      log.debug("Leaving requirement(). Found.");
      return REQUIREMENTS[i];
    }
  }
  log.debug("Leaving requirement(). Not found.");
  return null;
}

// A result is the pair every check returns: whether the act may proceed, and
// everything worth saying about it. `ok` is false only when a MUST failed —
// SHOULD findings are reported and do not stop anything, which is the whole
// difference between the two words.
function result(findings) {
  log.debug("Entering result().");
  var blocking = findings.filter(function (f) { return f.level === MUST; });
  log.debug("Leaving result(). blocking=" + blocking.length);
  return {
    ok: blocking.length === 0,
    blocked: blocking,
    findings: findings
  };
}


// ---------------------------------------------------------------------------
// The transaction record — sections 1.9, 2.4 and 3.
// ---------------------------------------------------------------------------

// Start one. Everything the response will be judged against is frozen here, at
// the moment the request is built, and nothing reads it off the configuration
// afterwards: the fields on the page are editable while a request is in
// flight, and judging a response against a value changed after the question
// was asked refuses a server for answering correctly. (The mock STS learned
// the same lesson on its Verifier — see its vc_verifier_config.js note.)
function beginTransaction(t) {
  log.debug("Entering beginTransaction().");
  var record = {
    issuer: t.issuer || "",
    state: t.state || "",
    nonce: t.nonce || "",
    codeVerifier: t.codeVerifier || "",
    codeChallengeMethod: t.codeChallengeMethod || "",
    clientId: t.clientId || "",
    redirectUri: t.redirectUri || "",
    responseType: t.responseType || "",
    responseMode: t.responseMode || "",
    scope: t.scope || "",
    resource: t.resource || "",
    dpop: !!t.dpop,
    issParameterAdvertised: !!t.issParameterAdvertised,
    stateConsumed: false,
    startedAt: Date.now()
  };
  sessionStore().setItem(TRANSACTION_KEY, JSON.stringify(record));
  log.debug("Leaving beginTransaction(). state=" + record.state);
  return record;
}

function transaction() {
  log.debug("Entering transaction().");
  var raw = sessionStore().getItem(TRANSACTION_KEY);
  if (!raw) {
    log.debug("Leaving transaction(). None.");
    return null;
  }
  try {
    var parsed = JSON.parse(raw);
    log.debug("Leaving transaction(). Found.");
    return parsed;
  } catch (e) {
    // Corrupt or from an older build. Treating it as absent is right: a
    // transaction that cannot be read cannot be the one this response belongs
    // to, and section 2 then refuses the response rather than accepting it.
    log.debug("Leaving transaction(). Unreadable, treated as absent.");
    return null;
  }
}

function saveTransaction(record) {
  log.debug("Entering saveTransaction().");
  sessionStore().setItem(TRANSACTION_KEY, JSON.stringify(record));
  log.debug("Leaving saveTransaction().");
}

function clearTransaction() {
  log.debug("Entering clearTransaction().");
  sessionStore().removeItem(TRANSACTION_KEY);
  log.debug("Leaving clearTransaction().");
}


// The spent set: codes redeemed and refresh tokens replaced. Kept in
// sessionStorage with the transaction, for the same reason — it is about this
// browsing session, and a code from a previous one is not one this page could
// present anyway.
//
// Values are stored as a length-prefixed hash rather than whole, so that a
// debugger's own storage does not accumulate live credentials. It is not a
// security boundary — the token is in localStorage two keys away — but there
// is no reason for this list in particular to hold one.
function spentKeyOf(kind, value) {
  log.debug("Entering spentKeyOf(). kind=" + kind);
  var text = String(value || "");
  var hash = 0;
  for (var i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
  }
  log.debug("Leaving spentKeyOf().");
  return kind + ":" + text.length + ":" + (hash >>> 0).toString(16);
}

function spentList() {
  log.debug("Entering spentList().");
  var raw = sessionStore().getItem(SPENT_KEY);
  if (!raw) {
    log.debug("Leaving spentList(). Empty.");
    return [];
  }
  try {
    var parsed = JSON.parse(raw);
    log.debug("Leaving spentList(). n=" + parsed.length);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    // As transaction(): unreadable is treated as empty. The direction matters
    // less here — the worst case is that a replay is not caught — but a throw
    // in a click handler is worse than either.
    log.debug("Leaving spentList(). Unreadable, treated as empty.");
    return [];
  }
}

function markSpent(kind, value) {
  log.debug("Entering markSpent(). kind=" + kind);
  if (!value) {
    log.debug("Leaving markSpent(). Nothing to mark.");
    return;
  }
  var list = spentList();
  var key = spentKeyOf(kind, value);
  if (list.indexOf(key) === -1) {
    list.push(key);
  }
  // Capped so a long session cannot grow this without bound. 200 is far more
  // than any single debugging session produces; the oldest go first, which
  // means a very old code could in principle be replayed — a trade this list
  // is allowed to make and a token store would not be.
  while (list.length > 200) {
    list.shift();
  }
  sessionStore().setItem(SPENT_KEY, JSON.stringify(list));
  log.debug("Leaving markSpent().");
}

function isSpent(kind, value) {
  log.debug("Entering isSpent(). kind=" + kind);
  if (!value) {
    log.debug("Leaving isSpent(). Nothing to check.");
    return false;
  }
  var spent = spentList().indexOf(spentKeyOf(kind, value)) !== -1;
  log.debug("Leaving isSpent(). spent=" + spent);
  return spent;
}


// ---------------------------------------------------------------------------
// Which grants and response types survive section 1.11.
// ---------------------------------------------------------------------------

// The grant selector values this mode disables, and why each one:
//
//   implicit_grant                   the OAuth2 Implicit Grant itself
//   oidc_implicit_flow               id_token token — an access token from the
//                                    authorization endpoint
//   oidc_implicit_flow_id_token      no access token, but it IS the Implicit
//                                    Flow, which RFC 9700 says SHOULD NOT be
//                                    used
//   oidc_hybrid_code_token           carries token
//   oidc_hybrid_code_id_token_token  carries token
//   resource_owner                   section 5, not section 1
//
// What is deliberately NOT here is oidc_hybrid_code_id_token: it returns a
// code and an id_token and no access token, so nothing bearer-shaped reaches
// the address bar, and the id_token is exactly the code-injection defence
// section 3 asks for.
var DISABLED_GRANTS = [
  "implicit_grant",
  "oidc_implicit_flow",
  "oidc_implicit_flow_id_token",
  "oidc_hybrid_code_token",
  "oidc_hybrid_code_id_token_token",
  "resource_owner"
];

function grantAllowed(grant) {
  log.debug("Entering grantAllowed(). grant=" + grant);
  var allowed = DISABLED_GRANTS.indexOf(String(grant)) === -1;
  log.debug("Leaving grantAllowed(). allowed=" + allowed);
  return allowed;
}

// The reason a grant is disabled, for the tooltip and the report. Written per
// grant rather than as one sentence, because "not allowed in RFC 9700 mode" on
// six controls tells a reader nothing about which rule they have met.
function grantRefusalReason(grant) {
  log.debug("Entering grantRefusalReason(). grant=" + grant);
  var reasons = {
    implicit_grant:
      "RFC 9700 section 2.1.2: the Implicit Grant returns an access token " +
      "from the authorization endpoint, where it lands in the address bar " +
      "and in history.",
    oidc_implicit_flow:
      "RFC 9700 section 2.1.2: response_type=id_token token returns an " +
      "access token from the authorization endpoint.",
    oidc_implicit_flow_id_token:
      "RFC 9700 section 2.1.2: the Implicit Flow SHOULD NOT be used. This " +
      "variant returns no access token, but the response still carries a " +
      "credential in the URL fragment and there is no code to bind.",
    oidc_hybrid_code_token:
      "RFC 9700 section 2.1.2: 'code token' returns an access token from " +
      "the authorization endpoint.",
    oidc_hybrid_code_id_token_token:
      "RFC 9700 section 2.1.2: 'code id_token token' returns an access " +
      "token from the authorization endpoint.",
    resource_owner:
      "RFC 9700 section 2.4: the Resource Owner Password Credentials grant " +
      "MUST NOT be used. It hands the user's password to the client and " +
      "cannot carry a second factor."
  };
  log.debug("Leaving grantRefusalReason().");
  return reasons[String(grant)] || "";
}


// ---------------------------------------------------------------------------
// Check 1 — the authorization request. Sections 1, 2, 4, 5, 7, 8 and 10.
//
// Called from oauth2_oidc_1.js when the Authorization Endpoint button is
// pressed, BEFORE the browser is navigated. Everything it needs is passed in;
// it reads no field itself.
//
//   req = {
//     grant, responseType, authorizationEndpoint, redirectUri, clientId,
//     clientSecret, scope, resource, state, nonce, usePKCE,
//     codeChallengeMethod, endpoints: {label: url, ...}, sslValidate,
//     metadata: <the discovery document or null>, metadataUrl,
//     dpopEnabled, backendAvailable
//   }
// ---------------------------------------------------------------------------
function checkAuthorizationRequest(req) {
  log.debug("Entering checkAuthorizationRequest().");
  var findings = [];
  var isCodeFlow = /(^|\s)code(\s|$)/.test(String(req.responseType || ""));
  // RFC 8628's Device Authorization Grant is not a browser redirect: there is
  // no redirect_uri, no state, no nonce and no PKCE to check, and the request
  // goes to the device authorization endpoint rather than the authorization
  // one. Running the redirect rules against it would refuse a perfectly
  // compliant device flow for lacking parameters it does not have — which
  // reads as the mode being broken rather than as the flow being wrong. What
  // still applies is every rule about TLS, metadata and least privilege.
  var deviceFlow = !!req.deviceFlow;

  // -- section 1.11 / 1.12 / 5.1 / 10.5: which flow ------------------------
  if (!grantAllowed(req.grant)) {
    var id = (req.grant === "resource_owner") ? "5.1" : "1.11";
    findings.push(finding(id, MUST, grantRefusalReason(req.grant)));
  } else if (isCodeFlow) {
    findings.push(finding("1.12", INFO,
      "response_type=" + req.responseType + " returns an authorization " +
      "code and no access token from the authorization endpoint."));
  }

  // -- section 1.1 / 1.2 / 1.3: the redirect URI ---------------------------
  var redirect = deviceFlow ? "" : String(req.redirectUri || "");
  if (deviceFlow) {
    findings.push(finding("1.1", INFO,
      "The Device Authorization Grant has no redirect_uri: the response " +
      "comes back on the token endpoint rather than through the browser, so " +
      "sections 1.1 to 1.3 and 2.1 to 2.3 do not apply to it."));
  } else if (!redirect) {
    findings.push(finding("1.1", MUST, "No redirect_uri is configured."));
  } else if (redirect.indexOf("*") !== -1) {
    findings.push(finding("1.2", MUST,
      "redirect_uri contains '*'. A pattern cannot be matched exactly: " +
      redirect));
  } else {
    var redirectUrl = parseUrl(redirect);
    if (!redirectUrl) {
      findings.push(finding("1.1", MUST,
        "redirect_uri is not an absolute URI: " + redirect));
    } else {
      if (redirectUrl.hash) {
        findings.push(finding("1.1", MUST,
          "redirect_uri carries a fragment, which a redirect URI may not: " +
          redirect));
      }
      var redirectTls = tlsProblem("redirect_uri", redirect);
      if (redirectTls) {
        findings.push(finding("1.3", MUST, redirectTls));
      } else if (redirectUrl.protocol === "http:") {
        findings.push(finding("1.3", INFO,
          "redirect_uri is http on the loopback interface, which RFC 8252 " +
          "permits — including a variable port."));
      }
    }
  }

  // -- section 1.4: where the request is going -----------------------------
  var authzTls = deviceFlow
    ? tlsProblem("The device authorization endpoint",
                 req.deviceAuthorizationEndpoint)
    : tlsProblem("The authorization endpoint", req.authorizationEndpoint);
  if (authzTls) {
    findings.push(finding("1.4", MUST, authzTls));
  }

  // -- section 8.1: every other endpoint too -------------------------------
  var endpoints = req.endpoints || {};
  Object.keys(endpoints).forEach(function (label) {
    var problem = tlsProblem(label, endpoints[label]);
    if (problem) {
      findings.push(finding("8.1", MUST, problem));
    }
  });

  // -- section 8.2: certificate validation ---------------------------------
  if (req.sslValidate === false || req.sslValidate === "false") {
    findings.push(finding("8.2", MUST,
      "Certificate validation is switched off. RFC 9700 section 2.5 asks " +
      "for TLS, and TLS without validation authenticates nobody."));
  }

  // -- sections 1.6 / 1.7: PKCE --------------------------------------------
  if (isCodeFlow && !deviceFlow) {
    if (!req.usePKCE) {
      var level = req.clientSecret ? SHOULD : MUST;
      findings.push(finding("1.6", level,
        req.clientSecret
          ? "PKCE is off. RFC 9700 states it at SHOULD for a confidential " +
            "client; this client is configured with a secret."
          : "PKCE is off and this is a public client (no client secret), " +
            "where RFC 9700 states it at MUST."));
    } else if (String(req.codeChallengeMethod || "").toUpperCase() !== "S256") {
      findings.push(finding("1.7", MUST,
        "The PKCE method is '" + req.codeChallengeMethod + "'. S256 is what " +
        "RFC 9700 asks for; 'plain' offers no protection against an " +
        "attacker who can read the authorization request."));
    }
  }

  // -- section 2.1: state --------------------------------------------------
  if (!req.state && !deviceFlow) {
    findings.push(finding("2.1", MUST,
      "No state value. RFC 9700 section 2.1 requires a one-time state " +
      "unless PKCE support has been verified, and 1.10 cannot always " +
      "verify it."));
  }

  // -- section 3.3: nonce on an authentication request ----------------------
  var wantsIdToken = /id_token/.test(String(req.responseType || "")) ||
      /(^|\s)openid(\s|$)/.test(String(req.scope || ""));
  if (wantsIdToken && !req.nonce && !deviceFlow) {
    findings.push(finding("3.3", MUST,
      "This is an OpenID Connect authentication request and it carries no " +
      "nonce. There would be nothing for section 3.2 to validate."));
  }

  // -- section 7.1 / 7.2: metadata -----------------------------------------
  var metadata = req.metadata || null;
  if (!metadata || !Object.keys(metadata).length) {
    findings.push(finding("7.1", MUST,
      "No authorization server metadata has been retrieved. In RFC 9700 " +
      "mode the endpoints must come from the server's own document rather " +
      "than being typed, which is what removes the misconfiguration this " +
      "section is about."));
  } else {
    var issuerProblem = issuerMismatch(metadata.issuer, req.metadataUrl);
    if (issuerProblem) {
      findings.push(finding("7.2", MUST, issuerProblem));
    }
    findings = findings.concat(metadataFindings(metadata, req));
  }

  // -- section 4.1: sender constraint --------------------------------------
  if ((isCodeFlow || deviceFlow) && !req.dpopEnabled) {
    findings.push(finding("4.1", SHOULD,
      "DPoP is off, so the access token will be a bearer token: whoever " +
      "holds it can use it. RFC 9700 section 2.2.1 recommends a " +
      "sender-constrained token."));
  }

  // -- section 4.2: audience restriction ------------------------------------
  if (!req.resource) {
    findings.push(finding("4.2", SHOULD,
      "No RFC 8707 resource indicator was sent, so the server decides the " +
      "token's audience. RFC 9700 section 2.3 asks that a token name the " +
      "resource server it is for."));
  }

  // -- section 4.3: least privilege ------------------------------------------
  if (!String(req.scope || "").trim()) {
    findings.push(finding("4.3", SHOULD,
      "No scope was requested. On many servers that means the client's " +
      "full registered scope, which is the opposite of least privilege."));
  }

  // -- section 6.2: how the secret will travel -------------------------------
  if (req.clientSecret && req.authStyle === "post") {
    findings.push(finding("6.2", SHOULD,
      "The client secret will be sent in the request body " +
      "(client_secret_post). client_secret_basic keeps it out of anything " +
      "that logs a body."));
  }

  var out = result(findings);
  log.debug("Leaving checkAuthorizationRequest(). ok=" + out.ok +
            ", findings=" + findings.length);
  return out;
}


// RFC 8414 section 3.3 and OIDC Discovery: the issuer identifier is the
// metadata URL with the well-known path segment removed. Returns a sentence or
// null.
//
// Both layouts are accepted, because both are in use: the OIDC form appends
// /.well-known/openid-configuration to the issuer, and the RFC 8414 form
// INSERTS /.well-known/oauth-authorization-server after the host, ahead of any
// path. A check that knew only one of them would report every server using the
// other as an impostor.
function issuerMismatch(issuer, metadataUrl) {
  log.debug("Entering issuerMismatch().");
  if (!issuer || !metadataUrl) {
    log.debug("Leaving issuerMismatch(). Not enough to compare.");
    return null;
  }
  var docUrl = parseUrl(metadataUrl);
  var issUrl = parseUrl(issuer);
  if (!docUrl || !issUrl) {
    log.debug("Leaving issuerMismatch(). Unparseable.");
    return null;
  }
  if (docUrl.origin !== issUrl.origin) {
    log.debug("Leaving issuerMismatch(). Different origin.");
    return "The metadata claims issuer " + issuer + " but was retrieved " +
        "from " + docUrl.origin + ". A document speaking for another origin " +
        "is the simplest form of the mix-up attack RFC 9700 section 4.4 " +
        "describes.";
  }
  var path = docUrl.pathname;
  var issPath = issUrl.pathname.replace(/\/$/, "");
  // OIDC Discovery: <issuer>/.well-known/openid-configuration
  var suffixMatch = path.replace(/\/\.well-known\/[^/]+$/, "");
  // RFC 8414: /.well-known/oauth-authorization-server<issuer path>
  var prefixMatch = path.replace(/^\/\.well-known\/[^/]+/, "");
  if (suffixMatch.replace(/\/$/, "") === issPath ||
      prefixMatch.replace(/\/$/, "") === issPath) {
    log.debug("Leaving issuerMismatch(). Matches.");
    return null;
  }
  log.debug("Leaving issuerMismatch(). Path mismatch.");
  return "The metadata claims issuer " + issuer + " but was retrieved from " +
      metadataUrl + ". RFC 8414 section 3.3 requires the issuer to be that " +
      "URL with the well-known path removed.";
}


// Sections 1.10, 7.3 and 7.4: what the document says about itself.
function metadataFindings(metadata, req) {
  log.debug("Entering metadataFindings().");
  var findings = [];
  var methods = metadata.code_challenge_methods_supported;
  if (!methods || !methods.length) {
    findings.push(finding("1.10", SHOULD,
      "The metadata does not advertise code_challenge_methods_supported, " +
      "so PKCE support cannot be verified. RFC 9700 section 2.1 says PKCE " +
      "MUST NOT be relied on for CSRF protection in that case — which is " +
      "why state is still required here."));
  } else if (methods.indexOf("S256") === -1) {
    findings.push(finding("7.3", SHOULD,
      "code_challenge_methods_supported does not include S256: " +
      methods.join(", ")));
  } else {
    findings.push(finding("7.3", INFO,
      "The server advertises S256 in code_challenge_methods_supported."));
  }

  var responseTypes = metadata.response_types_supported;
  if (responseTypes && responseTypes.length && req.responseType &&
      responseTypes.indexOf(req.responseType) === -1) {
    findings.push(finding("7.4", SHOULD,
      "response_type '" + req.responseType + "' is not in " +
      "response_types_supported: " + responseTypes.join(", ")));
  }

  log.debug("Leaving metadataFindings(). n=" + findings.length);
  return findings;
}


// Section 10.4: should this request ask for form_post?
//
// Two conditions, and the second is the one that is easy to forget. The server
// has to advertise it — asking for a response mode a server does not implement
// gets an error or, worse, a silent fall back to query. And THIS BUILD has to
// have somewhere to receive a POST: the deployed static sites have no
// /callback of ours at all, so a form_post response there would arrive
// nowhere.
function wantsFormPost(metadata, backendAvailable) {
  log.debug("Entering wantsFormPost().");
  if (backendAvailable === false) {
    log.debug("Leaving wantsFormPost(). No backend to receive a POST.");
    return false;
  }
  var modes = metadata && metadata.response_modes_supported;
  var advertised = !!modes && modes.indexOf("form_post") !== -1;
  log.debug("Leaving wantsFormPost(). advertised=" + advertised);
  return advertised;
}


// ---------------------------------------------------------------------------
// Check 2 — the authorization response. Sections 2, 10 and 11.
//
// Called from oauth2_oidc_2.js on page load, once the response parameters have
// been collected from the query string, the fragment, or the form_post
// landing.
//
//   resp = { state, iss, code, error, errorDescription, accessToken, idToken }
// ---------------------------------------------------------------------------
function checkAuthorizationResponse(resp) {
  log.debug("Entering checkAuthorizationResponse().");
  var findings = [];
  var record = transaction();

  // An error response is judged differently: there is no code to protect, and
  // the checks that matter are section 2's (was this even our transaction) and
  // section 11's (should the server have redirected at all).
  if (resp.error) {
    if (resp.error === "invalid_client" ||
        resp.error === "unauthorized_client") {
      findings.push(finding("11.2", SHOULD,
        "The server redirected an error of '" + resp.error + "' back to the " +
        "redirect_uri. RFC 9700 section 4.10.1 says an authorization server " +
        "MUST NOT redirect when the client_id or redirect_uri could not be " +
        "validated — an error about the client's identity is exactly that " +
        "case."));
    }
  }

  if (!record) {
    findings.push(finding("2.4", MUST,
      "No authorization transaction is recorded in this browser session, so " +
      "there is nothing to judge this response against. Start the flow from " +
      "the authorization request rather than by loading this URL."));
    var earlyOut = result(findings);
    log.debug("Leaving checkAuthorizationResponse(). No transaction.");
    return earlyOut;
  }

  // -- sections 2.1 / 2.2 / 2.3: state --------------------------------------
  if (!resp.state) {
    findings.push(finding("2.2", MUST,
      "The response carries no state. One was sent (" + record.state + "), " +
      "so this response cannot be tied to the request that started it."));
  } else if (record.stateConsumed) {
    findings.push(finding("2.3", MUST,
      "This state has already been used. RFC 9700 requires a one-time " +
      "state, so a second delivery of the same authorization response — a " +
      "reload, or a back button — is refused rather than replayed."));
  } else if (resp.state !== record.state) {
    findings.push(finding("2.2", MUST,
      "state does not match. The response carries '" + resp.state + "' and " +
      "this session sent '" + record.state + "'."));
  } else {
    findings.push(finding("2.2", INFO,
      "state matches the value sent with this transaction."));
  }

  // -- sections 2.5 / 2.6: RFC 9207 iss -------------------------------------
  if (resp.iss) {
    if (!record.issuer) {
      findings.push(finding("2.4", SHOULD,
        "The response carries iss=" + resp.iss + " but no issuer was " +
        "recorded for the request, so there is nothing to compare it to."));
    } else if (resp.iss !== record.issuer) {
      findings.push(finding("2.5", MUST,
        "The authorization response was issued by '" + resp.iss + "' and " +
        "the request was sent to '" + record.issuer + "'. That is the " +
        "mix-up attack RFC 9207 exists to detect."));
    } else {
      findings.push(finding("2.5", INFO,
        "iss matches the issuer this transaction was sent to."));
    }
  } else if (record.issParameterAdvertised) {
    findings.push(finding("2.6", MUST,
      "The server advertises authorization_response_iss_parameter_supported " +
      "and the response carries no iss. Its absence is meaningful precisely " +
      "because the server said it would be there."));
  } else {
    findings.push(finding("2.5", SHOULD,
      "The response carries no iss parameter (RFC 9207) and the server does " +
      "not advertise support for one. The ID Token's iss claim is checked " +
      "instead — see 2.7 — which is the fallback RFC 9700 names."));
  }

  var out = result(findings);
  log.debug("Leaving checkAuthorizationResponse(). ok=" + out.ok);
  return out;
}


// Mark this response's state used. Separate from the check so that a refusal
// does not burn the value — a state consumed by a response that was rejected
// would make the SECOND, legitimate delivery fail for the wrong reason and
// report the wrong rule.
function consumeState() {
  log.debug("Entering consumeState().");
  var record = transaction();
  if (record) {
    record.stateConsumed = true;
    saveTransaction(record);
  }
  log.debug("Leaving consumeState().");
}


// ---------------------------------------------------------------------------
// Check 3 — before the token request. Sections 3.1 and 5.1.
// ---------------------------------------------------------------------------
function checkTokenRequest(req) {
  log.debug("Entering checkTokenRequest().");
  var findings = [];

  if (req.grantType === "password") {
    findings.push(finding("5.1", MUST, grantRefusalReason("resource_owner")));
  }

  if (req.grantType === "authorization_code") {
    if (!req.code) {
      findings.push(finding("3.1", MUST,
        "There is no authorization code to redeem."));
    } else if (isSpent("code", req.code)) {
      findings.push(finding("3.1", MUST,
        "This authorization code has already been redeemed from this " +
        "session. RFC 9700 section 4.5 makes a code single-use; presenting " +
        "it twice is what a code-replay attack looks like from the " +
        "server's side."));
    }
    if (!req.codeVerifier) {
      var record = transaction();
      if (record && record.codeVerifier) {
        findings.push(finding("1.6", MUST,
          "A code_challenge was sent with the authorization request but no " +
          "code_verifier is being sent with the token request. The " +
          "exchange would fail, and on a server that does not enforce PKCE " +
          "it would succeed with the protection silently absent."));
      }
    }
  }

  if (req.grantType === "refresh_token" &&
      isSpent("refresh", req.refreshToken)) {
    findings.push(finding("9.1", MUST,
      "This refresh token was replaced by a rotated one. RFC 9700 section " +
      "4.14.2 says the previous token is invalidated on rotation, so " +
      "sending it again is a replay — and a server that answers it has a " +
      "defect worth finding another way."));
  }

  var out = result(findings);
  log.debug("Leaving checkTokenRequest(). ok=" + out.ok);
  return out;
}


// Record that a code has been presented. Called when the token request goes
// out, not when it succeeds: a code presented and refused is still a code that
// has been presented, and re-presenting it is still the thing section 3
// forbids.
function noteCodeRedeemed(code) {
  log.debug("Entering noteCodeRedeemed().");
  markSpent("code", code);
  log.debug("Leaving noteCodeRedeemed().");
}


// ---------------------------------------------------------------------------
// Check 4 — the token response. Sections 3.2, 4, 9 and 13.
//
//   tr = { data, grantType, clientId, requestedScope, previousRefreshToken }
//
// This is the one whose failure has to STOP something. RFC 9700 section 4.5.3:
// the client MUST NOT use any token until the ID Token's nonce has been
// validated. So the caller's contract is: if `ok` is false, the token set is
// discarded — not rendered, not written to Token History, not offered to the
// UserInfo or introspection links, not used to refresh.
// ---------------------------------------------------------------------------
function checkTokenResponse(tr) {
  log.debug("Entering checkTokenResponse().");
  var findings = [];
  var data = tr.data || {};
  var record = transaction();

  // -- section 3.2: the nonce ------------------------------------------------
  if (data.id_token) {
    var claims = decodeClaims(data.id_token);
    if (!claims) {
      findings.push(finding("3.2", MUST,
        "The ID Token could not be decoded, so its nonce cannot be checked " +
        "and no token from this response may be used."));
    } else {
      if (record && record.nonce) {
        if (!claims.nonce) {
          findings.push(finding("3.2", MUST,
            "A nonce was sent with the authentication request and the ID " +
            "Token carries none. Without it there is no defence against a " +
            "code injected from another session."));
        } else if (claims.nonce !== record.nonce) {
          findings.push(finding("3.2", MUST,
            "The ID Token's nonce is '" + claims.nonce + "' and this " +
            "session sent '" + record.nonce + "'. The token set has been " +
            "discarded."));
        } else {
          findings.push(finding("3.2", INFO,
            "The ID Token's nonce matches the value sent with this " +
            "transaction."));
        }
      }

      // -- section 2.7: the ID Token's issuer -------------------------------
      if (record && record.issuer) {
        if (!claims.iss) {
          findings.push(finding("2.7", MUST,
            "The ID Token carries no iss claim."));
        } else if (claims.iss !== record.issuer) {
          findings.push(finding("2.7", MUST,
            "The ID Token was issued by '" + claims.iss + "' and this " +
            "transaction was sent to '" + record.issuer + "'."));
        } else {
          findings.push(finding("2.7", INFO,
            "The ID Token's iss matches the issuer this transaction was " +
            "sent to."));
        }
      }

      // -- section 13.1: is the subject confusable with the client? ---------
      if (claims.sub && tr.clientId && claims.sub === tr.clientId &&
          tr.grantType !== "client_credentials") {
        findings.push(finding("13.1", SHOULD,
          "The ID Token's sub is the client_id. A resource server reading " +
          "this token cannot tell the client from the resource owner, " +
          "which is the collision RFC 9700 section 4.13 is about."));
      }
    }
  }

  // -- section 4.1: was the token actually bound? ----------------------------
  if (record && record.dpop) {
    var tokenType = String(data.token_type || "");
    if (tokenType.toLowerCase() !== "dpop") {
      findings.push(finding("4.1", SHOULD,
        "DPoP was requested but the token came back as token_type='" +
        tokenType + "'. Asking for a bound token does not produce one; this " +
        "token is a bearer token."));
    } else {
      findings.push(finding("4.1", INFO,
        "The access token came back DPoP-bound (token_type=DPoP)."));
    }
  }

  // -- section 4.2: audience -------------------------------------------------
  var accessClaims = decodeClaims(data.access_token);
  if (accessClaims) {
    if (!accessClaims.aud) {
      findings.push(finding("4.2", SHOULD,
        "The access token carries no aud claim, so it names no resource " +
        "server and any of them may accept it."));
    } else {
      var audience = [].concat(accessClaims.aud);
      findings.push(finding("4.2", INFO,
        "The access token's audience is: " + audience.join(", ")));
      if (audience.length > 3) {
        findings.push(finding("4.2", SHOULD,
          "The access token names " + audience.length + " audiences. RFC " +
          "9700 section 2.3 asks for one resource server, or a small set."));
      }
    }
  }

  // -- section 4.3: least privilege ------------------------------------------
  if (data.scope && tr.requestedScope) {
    var granted = String(data.scope).split(/\s+/).filter(Boolean);
    var asked = String(tr.requestedScope).split(/\s+/).filter(Boolean);
    var extra = granted.filter(function (s) {
      return asked.indexOf(s) === -1;
    });
    if (extra.length) {
      findings.push(finding("4.3", SHOULD,
        "The server granted scopes that were not requested: " +
        extra.join(", ") + ". A token wider than the request is not least " +
        "privilege, whatever the request asked for."));
    }
  }

  // -- section 9.2: rotation and constraint on the refresh token -------------
  if (data.refresh_token) {
    if (tr.previousRefreshToken &&
        data.refresh_token !== tr.previousRefreshToken) {
      findings.push(finding("9.1", INFO,
        "The server rotated the refresh token. The previous one has been " +
        "marked spent and will not be sent again."));
    } else if (tr.previousRefreshToken &&
               data.refresh_token === tr.previousRefreshToken) {
      var bound = String(data.token_type || "").toLowerCase() === "dpop";
      findings.push(finding("9.2", bound ? INFO : SHOULD,
        bound
          ? "The refresh token was not rotated, but the token set is " +
            "DPoP-bound. RFC 9700 section 4.14.2 accepts sender constraint " +
            "OR rotation."
          : "The server returned the SAME refresh token and the token set " +
            "is not sender-constrained. RFC 9700 section 4.14.2 requires " +
            "one of the two for a public client."));
    }
  }

  var out = result(findings);
  log.debug("Leaving checkTokenResponse(). ok=" + out.ok +
            ", findings=" + findings.length);
  return out;
}


// Called after a refresh response that carried a new refresh token, so the old
// one can never be sent again (section 9.1). Separate from checkTokenResponse
// so that a caller which decided to discard the token set does not also mark
// the previous token spent — leaving the session with neither.
function noteRefreshRotated(previous, current) {
  log.debug("Entering noteRefreshRotated().");
  if (previous && current && previous !== current) {
    markSpent("refresh", previous);
  }
  log.debug("Leaving noteRefreshRotated().");
}


// Decode a JWT's claims without verifying anything. Every use of this is a
// check whose failure is reported, never a decision to trust: the signature is
// the server's business and the debugger has a whole page for inspecting it.
function decodeClaims(token) {
  log.debug("Entering decodeClaims().");
  if (!token || typeof token !== "string") {
    log.debug("Leaving decodeClaims(). Nothing to decode.");
    return null;
  }
  var parts = token.split(".");
  if (parts.length < 2) {
    log.debug("Leaving decodeClaims(). Not a JWT.");
    return null;
  }
  try {
    var b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 = b64 + "=";
    }
    var json = (typeof atob === "function")
      ? atob(b64)
      : Buffer.from(b64, "base64").toString("binary");
    var claims = JSON.parse(decodeURIComponent(escape(json)));
    log.debug("Leaving decodeClaims(). Decoded.");
    return claims;
  } catch (e) {
    // An opaque access token is the ordinary case here, not an error: plenty
    // of servers issue one, and section 4.2's audience check simply has
    // nothing to read. Returning null says exactly that.
    log.debug("Leaving decodeClaims(). Not a decodable JWT: " + e.message);
    return null;
  }
}


// ---------------------------------------------------------------------------
// The report.
//
// One renderer, so that both pages say the same thing in the same shape. It
// returns a string of HTML for the caller to sanitize and insert — this module
// does not touch the DOM, for the reason at the top of the file.
// ---------------------------------------------------------------------------
function escapeHtml(s) {
  log.debug("Entering escapeHtml().");
  log.debug("Leaving escapeHtml().");
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// `title` names the act being reported on ("Authorization Request"), because
// this pane appears more than once in a run and a reader needs to know which
// step a row belongs to.
function report(title, res) {
  log.debug("Entering report(). title=" + title);
  var findings = (res && res.findings) || [];
  var html = '<div class="dbg-pane rfc9700-report">' +
      '<legend class="dbg-legend">RFC 9700 — ' + escapeHtml(title) +
      '</legend><fieldset>';
  if (!findings.length) {
    html += "<p>Every applicable check passed.</p>";
  } else {
    html += '<table class="rfc9700-findings">' +
        "<tr><th>Section</th><th>Level</th><th>Requirement</th>" +
        "<th>Finding</th></tr>";
    findings.forEach(function (f) {
      var cls = f.level === MUST ? "dbg-bad"
        : (f.level === SHOULD ? "dbg-warn" : "dbg-ok");
      html += '<tr class="' + cls + '">' +
          "<td>" + escapeHtml(f.section + " (" + f.id + ")") + "</td>" +
          "<td>" + escapeHtml(f.level.toUpperCase()) + "</td>" +
          "<td>" + escapeHtml(f.title) + "</td>" +
          "<td>" + escapeHtml(f.message) + "</td></tr>";
    });
    html += "</table>";
  }
  if (res && res.ok === false) {
    html += "<p class=\"dbg-bad\"><strong>Refused.</strong> " +
        "One or more MUST-level requirements were not met, so this step did " +
        "not proceed. Clear the RFC 9700 checkbox in the Configuration " +
        "Parameters pane to send the request anyway and see what the server " +
        "does with it — which is frequently the more interesting " +
        "answer.</p>";
  }
  html += "</fieldset></div>";
  log.debug("Leaving report().");
  return html;
}


// The catalogue as a table, for the documentation pane and for the tests. It
// is the same rows the checks cite, which is what stops the two drifting.
function catalogueHtml() {
  log.debug("Entering catalogueHtml().");
  var html = '<table class="rfc9700-catalogue">' +
      "<tr><th>#</th><th>Level</th><th>Requirement</th><th>How this client " +
      "answers it</th><th>Notes</th></tr>";
  REQUIREMENTS.forEach(function (r) {
    html += "<tr><td>" + escapeHtml(r.id) + "</td><td>" +
        escapeHtml(r.level) + "</td><td>" + escapeHtml(r.title) +
        "</td><td>" + escapeHtml(r.enforced) + "</td><td>" +
        escapeHtml(r.note) + "</td></tr>";
  });
  html += "</table>";
  log.debug("Leaving catalogueHtml().");
  return html;
}


module.exports = {
  MODE_KEY: MODE_KEY,
  TRANSACTION_KEY: TRANSACTION_KEY,
  SPENT_KEY: SPENT_KEY,
  MUST: MUST,
  SHOULD: SHOULD,
  INFO: INFO,
  REQUIREMENTS: REQUIREMENTS,
  DISABLED_GRANTS: DISABLED_GRANTS,
  enabled: enabled,
  setEnabled: setEnabled,
  requirement: requirement,
  isLoopbackHost: isLoopbackHost,
  tlsProblem: tlsProblem,
  issuerMismatch: issuerMismatch,
  grantAllowed: grantAllowed,
  grantRefusalReason: grantRefusalReason,
  wantsFormPost: wantsFormPost,
  beginTransaction: beginTransaction,
  transaction: transaction,
  saveTransaction: saveTransaction,
  clearTransaction: clearTransaction,
  consumeState: consumeState,
  noteCodeRedeemed: noteCodeRedeemed,
  noteRefreshRotated: noteRefreshRotated,
  isSpent: isSpent,
  decodeClaims: decodeClaims,
  checkAuthorizationRequest: checkAuthorizationRequest,
  checkAuthorizationResponse: checkAuthorizationResponse,
  checkTokenRequest: checkTokenRequest,
  checkTokenResponse: checkTokenResponse,
  report: report,
  catalogueHtml: catalogueHtml
};
