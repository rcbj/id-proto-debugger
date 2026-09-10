# OAuth 2.0 and OpenID Connect — what is left to implement

**Status: a roadmap, not a record. Dated 2026-09-04.** Every "should" below is a proposal and nothing here has been built. It is written in the same voice as the rest of `docs/` — the reasoning attached to each decision, so the decision can be argued with later — and when an item lands, the paragraph describing it should move into that workflow's own notes and be deleted from here. A roadmap that still lists finished work is worse than no roadmap, because the next reader cannot tell which half is which.

The source list is Robert Broeckelmann's [*OAuth2 + OIDC: All of the Specs (2026 Edition)*](https://medium.com/@robert.broeckelmann/oauth2-oidc-all-of-the-specs-2026-edition-5fe3f63a6392), 18 August 2026 — sixty-five distinct documents across OAuth 2.0, OpenID Connect, OpenID Federation, FAPI, JARM and Shared Signals. Coverage was read from `client/public/supported_standards.html`, `client/src/`, `api/` and the mock STS at `../mock-sts`, at commit `4777cc1` on `feature/254-risc`.

**Twenty-five of the sixty-five are implemented, three are partial, thirty-seven are not started.** Those counts treat a document the article cites twice as one document, and its section-level citations of RFC 6749 (§4.2, §4.3, §4.4) as part of RFC 6749.

## The method, because it is what makes the list useful

The article grades each specification by *its own* maturity — final, implementer's draft, active draft, experimental. This document grades the same list by **our coverage of it, at each end separately**, and that separation is where the finding is.

A protocol needs a client and a server. This project has both: the debugger is the client, and the mock STS is the server the test suite drives it against. Several documents on the article's list already have **one end built and not the other** — almost always the mock's end, because the mock grew a server-side feature to make some other test possible and nothing ever came back for the client half. Those are not gaps in the ordinary sense. They are half-finished protocols, and finishing one costs a fraction of what a green-field family costs, because the far end already exists to test against and its behaviour is already correct.

Three of the six tier-1 items below are that shape. It is the reason the ordering at the end is not simply "most important first".

## Fix this first: `supported_standards.html` is stale

`client/public/supported_standards.html` still carries **CAEP 1.0 and RISC 1.0 under "Named here, and deliberately not implemented"**, each with the sentence *"The pipe it needs is all there; adding it is rows in one table."* Both landed — CAEP on 2026-09-03 (`448eb16`'s predecessor) and RISC on 2026-09-04 — and that file has not been touched since the SSF part-one commit (`22625e9`).

This matters more than an ordinary stale document. That page's entire stated purpose is in its own lead paragraph: *"a debugger that overstates its coverage is worse than one that lists nothing, because people use this to learn the protocols."* The failure mode it was written to prevent is overstatement, and it is currently **understating** by two final specifications — which is the same defect pointed the other way, and it makes the page's own promise unreliable. Both rows should move up into the Shared Signals section with what the workflow actually does against them.

While that file is open, one more row is worth a second look. The DPoP pane's note says the debugger *"does not do RFC 8705 token binding at an OAuth token endpoint."* That is still true of the debugger and is **no longer true of the mock**, which issues `cnf["x5t#S256"]` on access and refresh tokens and checks it at four protected endpoints. The page is about the debugger, so the sentence is not wrong — but it now describes a gap with a working far end, which is a different thing from a gap, and see RFC 8705 below.

## Tier 1 — six that are nearly free

Each of these already has most of its machinery in the tree: the far end built, or the engine written for a neighbouring workflow. None of them is a new page. Together they close the OAuth 2.0 core to the point where the FAPI profiles in tier 3 become a switch rather than a project.

### RFC 7523 §2.2 and RFC 7521 — JWT client authentication

**The largest asymmetry in the tree, and the cheapest to close.**

The mock genuinely verifies all six token-endpoint authentication methods — `client_auth.js` handles `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth` and `self_signed_tls_client_auth`, and its metadata advertises only what the verifier can actually check. The debugger sends exactly one of them: `"Basic " + btoa(formData.client_id + ":" + ...)`, at two call sites in `oauth2_oidc_2.js`.

The consequence is visible on the request page and reads as a bug. It has a field for `token_endpoint_auth_methods_supported`, `oauth2_oidc_1.js` reads the value out of the discovery document and picks a method from it — and then the only method it can perform is the weakest one on the list. It has been choosing between things it cannot do.

The work is a JWS with five claims (`iss`, `sub`, `aud`, `jti`, `exp`) sent as `client_assertion` beside `client_assertion_type`. `jws.js` already signs it, `key_material.js` already holds the key, and the mock already verifies both the HMAC and the asymmetric variants including the "this client registered no keys" refusal. **This is also the piece that makes RFC 9700's asymmetric-credential recommendation demonstrable rather than only describable** — `rfc9700.js` currently names `private_key_jwt` in its rules and the page cannot send one.

### RFC 9126 — Pushed Authorization Requests

Neither end has it, and the mock has been carrying a joke about that for a while: `require_pushed_authorization_requests` is one of its deliberately-unsatisfiable metadata knobs, catalogued in `authorization_servers.js` as *"RFC 9126. NOT IMPLEMENTED HERE — there is no PAR endpoint — so setting it true publishes a requirement this server cannot satisfy, which is exactly the misconfiguration a client's error path should survive."*

Building the endpoint turns a lie a client has to survive into a capability a client has to use, and it costs nothing to keep the lie: the knob stays, and it becomes possible to publish `require_pushed_authorization_requests: true` on a server that *does* have the endpoint, which is the more interesting misconfiguration anyway.

On the debugger side it is a POST before the redirect and a `request_uri` in the authorization URL. The request page already composes every parameter PAR would carry; what changes is where they go. **It is also the prerequisite the other three request-security items lean on** — JAR is usually delivered through it, and FAPI 2.0 requires it outright — so it should come before them even though it is not the most valuable of the four on its own.

### RFC 9101 — JWT-Secured Authorization Request (JAR)

The debugger already *consumes* a signed Request Object: `vc_presentation_1.js` and `sd_jwt_vp.js` fetch one from a `request_uri` and verify it, because that is how an OID4VP verifier presents its authorization request. What the tool cannot do is **produce** one on the OAuth2 request page, which is the direction an OAuth client actually needs.

So half of this is written and living in the wrong workflow. The interesting part of the work is not the signing — it is making the two halves share one implementation, the way `jws.js` and `common/xmldsig.js` are shared, rather than leaving a second reading of the same document in a second bundle. `docs/wsfed.md` records what happened the last time this tree had two readings of one specification, and a Request Object is exactly the kind of thing that acquires a private copy.

The mock publishes `request_parameter_supported: false` and `request_uri_parameter_supported: false` (`oauth-oidc/oauth2.js`), so both flip and the authorize endpoint grows a branch.

### RFC 8705 — mutual-TLS client authentication and certificate-bound tokens

The second one-sided gap, and the only item on this list that is currently written down as a **decision** rather than an omission.

The mock does both halves. `tls_client_auth` matches the client certificate's subject DN and `self_signed_tls_client_auth` its thumbprint; with `global.https` on, the main listener asks for a client certificate and a Token Request made with one is answered with `cnf["x5t#S256"]` on the access *and* refresh tokens, which four protected endpoints then check against the certificate the connection was made with.

The debugger has neither, and `supported_standards.html` lists RFC 8705 under *deliberately not implemented*, on the grounds that mutual TLS happens on the PKI page and not at a token endpoint. **That reasoning was sound when it was written and is weaker now.** `POST /tls/connect` already opens a mutual-TLS connection from the api with a client certificate the PKI page issued minutes earlier — which is precisely the connection a token request needs, made by precisely the component that would have to make it. The distance from "the api can open this connection" to "the api can send a token request over it" is smaller than the distance the original note was measuring.

The reason to want it: DPoP is implemented here in full, and RFC 8705 is the other way to sender-constrain a token. Having one and not the other means the tool can show what sender-constraining *is* but not what the choice between the two mechanisms costs, which is the actual question a person deploying either one has.

### RFC 9728 — Protected Resource Metadata

**The smallest item on this list by a wide margin, and the one with the most external pull behind it.**

`metadata_schema.js` is already a table-driven validator for three documents — RFC 8414 authorization server metadata, OID4VCI issuer metadata and the DIF DID configuration, exported as `validateAsMetadata`, `validateVciMetadata` and `validateDidConfiguration`. A fourth is rows in the same table plus a fetch.

The other half is the `WWW-Authenticate` challenge carrying `resource_metadata`, and it is the half worth doing for its own sake: it is how a client discovers its authorization server **from a 401 rather than from configuration**, which is a discovery direction nothing in this tree demonstrates. Every other metadata document here is fetched because the user typed an issuer into a field. This one arrives because a resource server refused a request, and that is a different mechanism a client author has to get right.

It is also what every MCP implementation now depends on, which is not a reason to implement a specification but is a reason to expect people to arrive looking for it.

### RFC 9701 — JWT Response for OAuth Token Introspection

The introspection page exists and describes every member of a JSON response. RFC 9701 is the same response as a signed JWT with `application/token-introspection+jwt` — one branch on the content type, then `jws.js`, then the existing describer, then a line saying the response's integrity was checked rather than assumed.

Worth doing in the same sitting as RFC 9728. Both are the **resource server's** side of an OAuth deployment, which is the side this tool has almost nothing on: it is a very good client and a reasonable authorization server and it has never modelled the thing holding the API.

## Tier 2 — a workflow's worth of work each

Real features rather than completions. Each lands in an existing page, and each answers a question somebody testing an identity provider actually has.

### OpenID Connect Front-Channel Logout 1.0, then Back-Channel Logout 1.0

**Front-channel is another one-sided gap and should be done first.**

The mock implements the provider's half in full — `oauth-oidc/frontchannel_logout.js`, the two discovery members, the two per-client registration members, the `sid` claim on an ID Token issued on a browser session, and a hidden iframe per registered `frontchannel_logout_uri` on every sign-out. Nothing exercises it from the client side, because the debugger's logout page does RP-Initiated Logout and stops there: it has no `frontchannel_logout_uri` to register and nothing to show when the iframe fires.

Registering one and reporting the `iss` and `sid` it arrives with is a small page and a genuinely hard thing to observe anywhere else — the request lands in a hidden iframe on somebody else's page, which is exactly the place a person cannot put a breakpoint.

**Back-channel logout is the harder half and the more interesting one.** The relying party receives a POSTed Logout Token, and a page cannot receive a POST — so it needs the api, for the same reason and in the same shape as RFC 8935 push delivery. `api/ssf_receiver.js` is the precedent and very nearly the pattern: a receiver hosted on the page's behalf, for the one thing a browser genuinely cannot do. The mock publishes `backchannel_logout_supported: false`, so both ends are new there.

The two together are also what the tree should say about **Session Management 1.0**, which the article lists as Final and which is in tier 3 below for reasons that are about browsers rather than about effort.

### JARM — JWT Secured Authorization Response Mode

JAR in the other direction: the authorization *response* arrives as a single `response` parameter holding a JWT. On the debugger this is one more branch on the response page, which already decodes and verifies a JWT against a JWKS for the ID Token — so the work is mostly recognising the five `response_mode` values (`jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt`) and reporting what the signature covered.

Ship it after JAR, so the pair reads as a pair. Neither end has it now.

### RFC 9470 — Step-Up Authentication Challenge Protocol

Small, and unusually well positioned here. Every piece is present and none of them is connected to the others:

* the request page already sends `acr_values` and `max_age`;
* the mock already computes **real** `acr` and `amr` values off how the person actually signed in — `["pwd","hwk"]`/`mfa` for a password plus a security key, `["hwk"]`/`1` for a passwordless WebAuthn sign-in, and nothing at all when no credential evidenced a factor;
* the WebAuthn relying party that produces those values is in the same process.

What is missing is the loop between them: a resource server answering `insufficient_user_authentication` with the `acr_values` it wanted, and a client that re-authorizes in response and comes back with a token that satisfies it. **The debugger is one of very few places that can show the whole round trip**, because it owns both the WebAuthn ceremony and the token request, and the interesting failure — the second authorization returns an `acr` that still does not satisfy the challenge — is invisible from either end alone.

### RFC 7522 and RFC 7523 §2.1 — the assertion grants

Neither `urn:ietf:params:oauth:grant-type:saml2-bearer` nor `...:jwt-bearer` appears anywhere in either repository.

RFC 7522 is the one to take seriously. **This is the only tool that already builds a signed SAML 2.0 assertion and composes an OAuth token request in the same application**, which is what RFC 7522 is: an assertion from one world presented as a grant in the other. Handing an assertion from the SAML workflow to the token endpoint is the bridge between the two protocol families this whole tree is organised around, and it is the exchange every enterprise migration off SAML actually performs. The mock has both assertion builders and the token endpoint already; the work is one grant handler on each side, plus the decision about how the two workflows hand the assertion across — `session_handoff.js` and `token_handoff.js` are the existing precedent for that.

RFC 7523 §2.1 is the same shape with a JWT and is nearly free once §2.2 (tier 1) is done, since the assertion construction is shared.

### OpenID Connect CIBA — Client-Initiated Backchannel Authentication

The decoupled flow: the client asks, the person approves somewhere else entirely, the client collects. Bigger than everything above it, because it needs a backchannel authentication endpoint, an approval surface on the mock, and all three token delivery modes.

The shape is one this tree has twice, though. The **poll** mode is very nearly the device grant's polling loop, `authorization_pending` and `slow_down` included, which `oauth2_oidc_2.js` already implements. **Ping** and **push** need a receiver the api hosts, which is the SSF push receiver's pattern for the third time. High real-world relevance — it is what banking and telco deployments use — and almost nothing debugs it.

### OpenID Connect for Identity Assurance 1.0

A claim that carries how it was verified, by whom, against which document, and when. It lands squarely in machinery that already exists: the IANA-registry-backed claim describer in `token_detail.js` and `jwt_tools.js`, and the mock's claim catalogues. It also sits naturally beside the SD-JWT VC workflow, since `verified_claims` and a verifiable credential are two answers to the same question — *what does this assertion actually prove, and who is standing behind it*.

Mostly a describer and a generator rather than a protocol, which is why it is at the bottom of this tier rather than the top: it adds understanding rather than an exchange.

## Tier 3 — the big ones

Each of these is a family rather than a document. Two are worth planning for now, because what happens in tier 1 decides how expensive they are later.

### FAPI 1.0 Parts 1 and 2, FAPI 2.0 Security Profile / Attacker Model / Message Signing

**This is the destination that makes tier 1 cohere, and it must not be started first.**

FAPI is a profile, not a protocol — which means it is exactly the shape of `client/src/rfc9700.js` and the mock's `oauth-oidc/oauth2_bcp.js`: a compliance mode that constrains what the existing workflow may send, with a table behind it saying which requirement each refusal comes from. The architecture for it is already written twice.

But every constraint it imposes names a document from tier 1. FAPI 2.0 requires PAR; requires sender-constrained tokens by mutual TLS or DPoP; requires asymmetric client authentication. FAPI 1.0 Advanced adds JARM, or a signed ID Token used as a detached signature. Build RFC 7523, RFC 9126, RFC 9101 and RFC 8705 first and FAPI is a second checkbox beside RFC 9700 with a table behind it. Build it first and it is five projects wearing one name, and the compliance mode ends up implementing its own PAR that nothing else can use.

### OpenID Federation 1.0 and 1.1, and Federation for OpenID Connect 1.1

**Worth stating clearly, because the name collides with something already in the tree and the collision will otherwise be read as coverage.**

The `--federation-only` test suite and the mock's `federation/` directory are **ordinary multi-protocol federation**: an identity provider trusting another identity provider, configured by hand, one relationship at a time, with a certificate on the relationship. That is a real feature and it is not this.

OpenID Federation is entity statements, a resolvable trust chain from a leaf up to a trust anchor, trust marks, and automatic client registration against a federation nobody configured pairwise. Nothing in either repository touches it — `entity_statement`, `trust_chain` and `trust_mark` each return nothing across both trees.

It is the largest remaining family on the article's list, it is what national eID schemes and the EUDI wallet ecosystem are built on, and it is a whole page plus a whole mock surface plus a trust-anchor fixture. **Plan it as its own `docs/*-plan.md`; do not slip it in beside something else.**

### Self-Issued OpenID Provider v2

Closer to done than it looks, because of where it sits. The VC presentation workflow already reads an OID4VP authorization request in all three of its forms, and `did_tools.js` already resolves `did:key` and `did:jwk` with the verification relationships honoured — which is most of what a self-issued ID Token's `sub` and `sub_jwk` need. SIOPv2 is the authentication half that sits beside the presentation half that most wallets ship together, so it completes the wallet story rather than starting a new one.

### OpenID Connect Session Management 1.0

Listed for completeness and ranked last on purpose. It is a Final specification and the mock already says in a comment that `check_session_iframe` is not implemented — but the browser has been closing the door on it for years. It depends on a cross-origin iframe polling a third-party cookie, which is the mechanism every browser is in the process of removing. Front-channel and back-channel logout are what replaced it in practice, and both are in tier 2.

If it is built at all, build it to **document why it stopped working** — which is a legitimate thing for a debugger to do, and is a different feature from implementing it.

## Already covered

Twenty-five of the article's documents are implemented and three are partial. This list is the cross-reference's output; `client/public/supported_standards.html` is the authoritative statement of what each one means here.

RFC 6749 · RFC 6750 · RFC 7636 · RFC 9700 · RFC 7009 · RFC 7662 · RFC 9068 · RFC 8414 · RFC 7591 · RFC 7592 · RFC 9207 · RFC 8628 · RFC 8693 · RFC 9396 · RFC 9449 · RFC 9901 · OpenID Connect Core 1.0 · Discovery 1.0 · Dynamic Client Registration 1.0 · RP-Initiated Logout 1.0 · Multiple Response Type Encoding Practices · Form Post Response Mode · Shared Signals Framework 1.0 · CAEP 1.0 · RISC 1.0

The three partials:

* **RFC 8252** — section 7.3's loopback port exception only, which is the one carve-out RFC 9700 mode's exact-match rule makes. The rest of the native-app guidance has nothing here to apply to.
* **RFC 9101** — consumed in the OID4VP workflow, not produced on the OAuth2 page. See tier 1.
* **RFC 9278** — the JWK Thumbprint **URI** form. `sd_jwt_vp.js` carries `"urn:ietf:params:oauth:jwk-thumbprint:holder"` as a placeholder default, which is the URN's shape with a word where the thumbprint goes. `jws.js` already computes the RFC 7638 thumbprint the URI wraps, so this is a twenty-line fix for whoever is next in that file.

**RFC 6819 needs no row.** RFC 9700 formally obsoletes it, and the compliance mode *is* that document.

## Named, and deliberately not queued

* **OAuth 2.1** (draft) — consolidation, and nearly everything it mandates is what RFC 9700 mode already enforces: PKCE everywhere, exact-string redirect URI matching, no implicit grant, no password grant. A second compliance mode would differ from the first in a handful of rows, and two nearly-identical modes is a worse thing to maintain than one. Revisit if it becomes an RFC.
* **OAuth 2.0 for Browser-Based Applications** (draft) — advice to application authors. There is no wire format to implement.
* **Native SSO for Mobile Apps** — needs two cooperating mobile applications and a device secret shared between them. This tree has no way to be either of them.
* **Incremental Authorization** (draft) — small, and it is `scope` plus a bookkeeping convention. Not nothing, but not a feature.
* **The five OIDF active drafts** — Claims Aggregation, Enterprise Extensions, Ephemeral Subject Identifier, Key Binding, and the three Federation sub-drafts. All still moving; implementing a red-status draft buys a maintenance burden rather than a capability.

**One exception inside that last bullet, worth watching by name: OpenID Provider Commands.** It is a provider telling a relying party to *do* something, which is the same inversion SSF is — aimed at provisioning instead of at sessions. The SSF, CAEP and RISC work just built the pipe it would want, and `docs/ssf.md`'s separation of pipe from vocabulary is exactly the seam a fourth vocabulary would land on. If it stabilises, it is cheaper here than anywhere.

## Suggested order

Sequenced so that each item leaves the next one cheaper, and so the first several land in pages that already exist.

1. **Update `client/public/supported_standards.html`** — CAEP and RISC are done and the page says they are not. An hour, and it restores the page's own promise.
2. **RFC 7523 §2.2 client authentication** — the mock already verifies all six methods; the debugger can send one. Pure one-sided gap, and it is the one the request page is already pretending to have.
3. **RFC 9728 and RFC 9701 together** — the resource server's side, in the metadata validator and the introspection page. Both small; neither is small on its own terms.
4. **RFC 9126 PAR** — the prerequisite the next two lean on, and it retires a metadata knob that currently lies on purpose.
5. **RFC 9101 JAR, then JARM** — produce a Request Object on the OAuth2 page, then read a signed response. Ship as a pair, and share the implementation with the OID4VP half rather than growing a second one.
6. **RFC 8705** — both halves on the debugger. The mock is already there and so is `POST /tls/connect`.
7. **Front-channel logout, then back-channel** — the mock's provider half is complete and unexercised; the back-channel receiver reuses `api/ssf_receiver.js`'s shape.
8. **RFC 7522 SAML 2.0 Bearer** — the bridge between the two protocol families this tree is organised around, which only this tool is positioned to build.
9. **RFC 9470 step-up** — closes the loop between the WebAuthn ceremony's `acr` and the token request.
10. **FAPI 2.0 as a profile** — a checkbox beside RFC 9700 once 2, 4, 5 and 6 are in, and a five-project rewrite if it is attempted before them.

OpenID Federation, CIBA, SIOPv2 and Identity Assurance each want a plan document of their own before they want a position in this list.
