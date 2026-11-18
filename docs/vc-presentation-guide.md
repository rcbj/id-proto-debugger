---
title: "Using the VC presentation workflow"
---

# Using the VC presentation workflow

The VC presentation workflow is the **VC Presentation** card on the landing
page. It makes the debugger a wallet: a Verifier asks for part of a
credential, and you choose what to send. It is four pages.
`vc-presentation-0.html` chooses the protocol and the flow.
`vc-presentation-1.html` reads the Verifier's request. `vc-presentation-2.html`
chooses what to disclose and sends the answer. `vc-presentation-3.html` shows
what was sent and what the Verifier answered.

The wallet presents four credential formats: `dc+sd-jwt` (SD-JWT VC),
`jwt_vc_json`, `ldp_vc` with a `bbs-2023` proof, and ISO mdoc (`mso_mdoc`). It
answers under three protocols: **OpenID4VP 1.0**, **OpenID4VC HAIP 1.0** and
**SIOPv2**.

These pages have no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## Before you start

From a checkout, follow [Getting started](getting-started.md). Then open
`https://localhost:3000` and pick **VC Presentation**.

### A credential from the issuance workflow

The wallet presents the credential the **VC Issuance** workflow left in this
browser. There is no import box on these pages. Run issuance first, against
an issuer that offers the format the Verifier will ask for. The last pages of
issuance offer **Present It (presentation workflow)**, which opens step 0. It
copies nothing: both workflows read the same browser storage.

The wallet holds one credential at a time. A Verifier that asks for one
format cannot be answered with another, so a `dc+sd-jwt` credential cannot
answer a request for `ldp_vc`.

No issuer in the test stacks mints `mso_mdoc`. The issuance pages read an mdoc
Credential Response, so an mdoc must come from an issuer that mints one.

Step 0 says what the wallet holds, under the configuration pane. For example:
*Holding a ... with N selectively-disclosable claim(s), and the holder key it
is bound to — so it can be presented.* With no credential it says *This
wallet is not holding a credential yet, so there is nothing to present.*

### The holder key

A credential is bound to a holder key that the wallet generated on issuance
step 2. The presentation is signed with the private half: a Key Binding JWT
for `dc+sd-jwt`, a Verifiable Presentation JWT for `jwt_vc_json`, and a device
signature for an mdoc.

Issuance step 2 has **Save this holder key pair in browser localStorage**
(row **Keep the key pair**), on by default.

* **On.** The key is in storage and the presentation pages find it.
* **Off.** The private half is never stored. Use **Download Key Pair** on
  issuance step 2 and keep the file. Presentation step 2 then shows a
  **Holder private key** field. Paste the file, or a bare private JWK, into
  it. The pasted key is used for that page load and is not stored.

Step 0 and step 1 treat the two cases differently. With saving off, a missing
key is an advisory and **Continue** stays on. With saving on and no key, the
key was never generated in this browser, there is nothing to paste, and step 1
blocks.

## Step 0: configure the Verifier and choose the protocol

### Configuration Parameters

An OpenID4VP Verifier publishes no discovery document, so these are set by
hand. **Save** stores them. **Clear All** removes them. **Restore Defaults**
fills the first three fields from the deployment's defaults and says
*Restored this suite's mock verifier. Save to apply.*

| Field | Restore Defaults on a local checkout | What it does |
|---|---|---|
| **Verifier website URL** | `http://localhost:9700/verifier` | The Verifier's own page where a person starts a verification. Every flow button sends you there. |
| **Verifier base URL** | `https://localhost:8081` | The Verifier's origin. The JWKS URL defaults under it. |
| **Verifier JWKS URL** | `https://localhost:8081/oauth2/jwks` | The keys a signed Request Object from a pre-registered client is checked against. |
| **x509 trust anchor (PEM)** | not filled | The root certificate for a Verifier named by `x509_hash` or `x509_san_dns`. Empty, the chain is still checked link by link and its top is reported as UNTRUSTED. |
| **Reach the Verifier through the debugger's api** | not changed | Two boxes: **through the api**, off by default, and **check the Verifier's TLS certificate on that route**, on by default. See [Sending through the api](#sending-through-the-api). |

The placeholders in the empty fields (`http://localhost:8081`, and so on) are
only hints. `https://localhost:8081` is iya-sts.

### Which protocol is the answer given under?

Three buttons. The default is **OpenID4VP 1.0**. The line under them names
the current choice. Choosing a protocol discards any request already read,
because that request was checked against other rules.

| | OpenID4VP 1.0 | OpenID4VC HAIP 1.0 | SIOPv2 |
|---|---|---|---|
| What it is | A presentation, as OpenID4VP allows it | A profile of OpenID4VP that removes the options | The wallet is its own OpenID Provider and signs an ID Token |
| `response_type` | `vp_token` | `vp_token` | `id_token`, or `vp_token id_token` with a presentation |
| How the request arrives | By value, or by reference (`request_uri`), signed or not | By reference only, as a signed Request Object | As OpenID4VP |
| Client Identifier prefixes checked | `redirect_uri`, `x509_hash`, `x509_san_dns`, and none (pre-registered) | `x509_hash` only | As OpenID4VP |
| Response modes | `direct_post`, `direct_post.jwt`, `fragment`, `query`, `form_post`, `post` | `direct_post.jwt` only | As OpenID4VP |
| Refused on step 1 | The OpenID4VP rules below | The OpenID4VP rules, plus a request that is not by reference, not signed, not `x509_hash`, not `direct_post.jwt` or not `vp_token` | The OpenID4VP rules, plus no `id_token` in `response_type`, no `scope=openid`, or no subject syntax both sides support |
| Warned on step 1 | An untrusted chain, a Request Object `typ` other than `oauth-authz-req+jwt` | Also a request not signed ES256, and a format other than `dc+sd-jwt` or `mso_mdoc` | As OpenID4VP |
| What is sent | The presentation | The same presentation, encrypted to the Verifier's key | A self-issued ID Token, alone or beside the presentation |

HAIP 1.0 profiles `dc+sd-jwt` and `mso_mdoc`. A `jwt_vc_json` or `ldp_vc`
credential is still presented under HAIP's signed request and encrypted
answer, and the `HAIP: format` row reports it as a departure from the
profile.

### How does the request reach the wallet?

Three flow buttons, each a card with what it means:

| Button | How the request travels |
|---|---|
| **Same device · Request by value** | The whole request in the query string, with a `redirect_uri:` Client Identifier. It cannot be signed. |
| **Same device · Signed request by reference** | `client_id` and `request_uri`. The wallet fetches a signed Request Object (RFC 9101) and checks it. |
| **Cross device · QR code** | The Verifier shows a QR code. You paste what it encodes into step 1. |

Under HAIP the by-value card is greyed out with *Not under HAIP 1.0, which
passes every request by reference as a signed Request Object.* Choosing HAIP
while that flow is selected switches to the signed one.

A flow button records the flow, discards any old request, and sends the
browser to the **Verifier website URL**. The status line says which format to
ask for there: *... asking for the `<format>` credential this wallet holds*.
On that site you choose how the request is made, and a same-device Verifier
sends the browser back to step 1 with the request in the query string.

With no Verifier website URL, the status says *There is no verifier website
configured to ask for a presentation. Set one above, or paste a request into
step 1 by hand.*, and the page opens step 1.

Every page shows the protocol and the flow under the step links, with a
**change** link back to step 0.

## Pointing it at a Verifier

### iya-sts

[iya-sts](https://rcbj.github.io/iya-sts/) is the Verifier at
`https://localhost:8081`. **Restore Defaults** fills its base URL and JWKS URL.

Its website is a separate service, iya-sts's development companion, at
`http://localhost:9700/verifier`. The test stacks run it; the plain
`docker-compose.yml` stack does not. Its form chooses the credential format,
by value or by reference, and same device or cross device. A same-device
start returns the browser to step 1 with the request.

The test suite starts HAIP and SIOPv2 requests through iya-sts's management
API instead: `POST https://localhost:8081/admin-api/verifications/start`.
That API needs an access token; see [iya-sts](mock-sts.md). The answer
carries a `requestUri` (`openid4vp://`, `haip-vp://` or `siopv2://`), which is
pasted into step 1.

For an `x509_hash` request, iya-sts publishes its trust anchor at
`https://localhost:8081/oid4vp/verifier-certificate`, as
`x509_hash.trust_anchor_pem`. The tests paste that into **x509 trust anchor
(PEM)**.

### walt.id

walt.id's `verifier-api2` runs on the containerized test stack and on
`keycloak-tests.yml`, behind a CORS proxy at `http://localhost:7003`. A
verification session is created with walt.id's own API,
`POST /verification-session/create`. Its answer carries
`fullAuthorizationRequestUrl` (by value) and
`bootstrapAuthorizationRequestUrl` (by reference). Paste either into step 1.

walt.id's verifier does not check that the DCQL query was answered. A
presentation that withholds a requested claim can be accepted. Step 3's
**Answered the request?** line is where that shows.

### Polaris

Polaris (`polaris-oid4vp`) is an independent OpenID4VP 1.0 and HAIP 1.0
Verifier. It is wired into the containerized test stack for one job only, at
`https://polaris:7010` inside the compose network, and is not published to
the host. The job chooses **OpenID4VC HAIP 1.0**, pastes Polaris's trust
anchor, and pastes its `haip-vp://` launch link into step 1. It uses
`request_uri_method=post`, so the wallet posts its metadata and a
`wallet_nonce`.

## Step 1: read the request

The request arrives in one of two ways:

* **In the query string**, when a Verifier sends the browser to
  `vc-presentation-1.html?...`. It is read on load.
* **Pasted.** Put an `openid4vp://` URI, an `https://` link carrying the same
  parameters, or the bare query string into **Request URI** under
  **Receive a Request (cross-device)**. Click **Read this Request**.

If the request names a `request_uri`, the wallet fetches the Request Object.
With `request_uri_method=post` it posts `wallet_metadata` and a
`wallet_nonce`, and refuses a Request Object that does not echo the nonce.
Nothing is sent to the Verifier on this page beyond that fetch, and nothing
is disclosed.

A request read here is kept across a reload. **Discard this request** drops
it. **Choose what to disclose →** is **Continue**.

### The panes

| Pane | What it shows |
|---|---|
| **What `<protocol>` Demands of This Request** | One row per rule of the chosen protocol, OK, **REFUSED** or **WARNING**. |
| **The Verifier's Authorization Request** | Where it came from, `client_id`, the identifier prefix and what it proves, the **Signature** verdict, `nonce`, `response_type / mode`, `response_uri`, `state`, `dcql_query`, `client_metadata`, and every parameter as received. |
| **What Is Being Asked For** | The DCQL query against the credential you hold. A claim in red is marked *(not in the credential you hold)*. A `vct` (or mdoc doctype) in red is a different kind of credential. |
| **Receive a Request (cross-device)** | The paste box and the buttons. |

With no `response_mode`, the page shows *(fragment, the OAuth 2.0 default)*.

### Reading the rules

A **REFUSED** row turns **Continue** off. A **WARNING** row is shown and the
wallet answers anyway.

| Rule | Level | Fails when |
|---|---|---|
| `response_type` | REFUSED | Not `vp_token` (OpenID4VP and HAIP). If it asks for `id_token`, the row says to choose SIOPv2 on step 0. |
| `nonce` | REFUSED | No nonce. |
| `dcql_query` | REFUSED | A `vp_token` request with no DCQL query. |
| `redirect_uri prefix` | REFUSED | A `redirect_uri:` request that is signed. |
| `redirect_uri target` | REFUSED | The answer would go somewhere other than the URL the Client Identifier names. |
| `x509_hash signed` / `x509_san_dns signed` | REFUSED | An x509 Client Identifier on an unsigned request. |
| `x509_hash` / `x509_san_dns` | REFUSED | The leaf certificate in `x5c` does not hash to, or does not name, the Client Identifier. |
| `request signature` | REFUSED | The Request Object does not verify with the leaf certificate's key. |
| `response host` | REFUSED | `x509_san_dns` only: the answer would go to another host. |
| `trust anchor` | WARNING | The chain does not reach the configured anchor, or no anchor is configured. |
| `typ` | WARNING | A signed Request Object whose `typ` is not `oauth-authz-req+jwt`. |
| `client_id match` | REFUSED | The `client_id` inside the signed request differs from the one the wallet was handed. |
| `wallet_nonce` | REFUSED | The Request Object does not echo the `wallet_nonce` the wallet posted. |
| `response_mode` | REFUSED | A mode the wallet cannot deliver. |
| `response_uri` / `redirect_uri` | REFUSED | No address for the chosen mode. |
| `encryption key` | REFUSED | `direct_post.jwt` with no key in `client_metadata.jwks` the wallet can encrypt to: ECDH-ES on P-256, or an ML-KEM or HPKE key (X-Wing among them) named by its `alg`. Under HAIP, ECDH-ES P-256 only. |
| `enc` | REFUSED | None of the Verifier's `encrypted_response_enc_values_supported` is one the wallet does (A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512). |
| `HAIP: request_uri`, `HAIP: signed`, `HAIP: x509_hash`, `HAIP: direct_post.jwt`, `HAIP: vp_token` | REFUSED | HAIP only. |
| `HAIP: ES256` | WARNING | HAIP only: the request is signed with another algorithm. |
| `HAIP: format` | WARNING | HAIP only: the format is not `dc+sd-jwt` or `mso_mdoc`. |
| `SIOPv2: id_token`, `SIOPv2: scope openid`, `SIOPv2: subject syntax` | REFUSED | SIOPv2 only. |

The status line above the request adds what the wallet itself lacks. These
also turn **Continue** off:

* the wallet holds no credential, or one that cannot be parsed;
* the Verifier asked for one format and the wallet holds another;
* the holder key is missing and saving is on;
* the Request Object's signature does not verify.

These are advisories and do not:

* the holder key is not kept in this browser by your choice on issuance
  step 2. You paste it on step 2.
* the credential is `ldp_vc`. Step 1 does not ask for a holder key. Step 2
  may, see [ldp_vc](#ldp_vc).
* the request asks for a SIOPv2 ID Token alone. No credential is presented.

A request that passes says *Request read ... under `<protocol>`. It asks for
N claim(s) ...*.

### Who is asking

| Prefix | What the wallet can conclude |
|---|---|
| `redirect_uri:` | The Client Identifier is the URL the answer goes to. The request cannot be signed. |
| none | A pre-registered client. A signed request is checked against **Verifier JWKS URL**. With no JWKS URL at all, the verdict says the signature cannot be checked, and the request is not refused. |
| `x509_hash:` | The SHA-256 of the leaf certificate in `x5c`. The request is checked with that certificate's key and its chain followed to the trust anchor. |
| `x509_san_dns:` | A DNS name in the leaf certificate. The answer must go to that host. |
| any other | Shown as it arrived, without a claim that it was validated. |

## Step 2: choose what to disclose and present

### What This Verifier Asked For

The Client Identifier (it becomes the `aud` of the holder proof), the
`nonce`, the claims requested, whether holder binding is required, and the
**Always visible** claims. Always-visible claims are in the issuer-signed JWT
itself and travel whatever you choose.

### Choose What To Disclose

One row per Disclosure, each marked *asked for* or *not asked for*. The
default selection is exactly what was asked for.

* **Only what was asked for** resets to that.
* **Everything (over-disclose)** selects every row.

The summary line counts the selection. It says in red what was asked for and
is not selected (*the presentation will be refused without it*), and what is
selected and was not asked for. The selection is kept across reloads.

What a row is depends on the format:

| Format | Rows | Holder proof |
|---|---|---|
| `dc+sd-jwt` | One per Disclosure | A Key Binding JWT: `typ` `kb+jwt`, the request's `nonce`, the Client Identifier as `aud`, `iat`, and `sd_hash` over the bytes sent |
| `jwt_vc_json` | Every claim listed, none selectable. The format has no selective disclosure, so every claim goes | A Verifiable Presentation JWT signed with the bound key |
| `ldp_vc` | One per value, named by its JSON pointer; the issuer's mandatory pointers are ticked and cannot be cleared | The `bbs-2023` derived proof over a reveal document, with the `nonce` as its presentation header; under holder binding, also a holder-signed `VerifiablePresentation` |
| `mso_mdoc` | One per element, named `namespace/element` | A device signature (COSE_Sign1, ES256) over the session transcript |
| `vc+sd-jwt` (W3C) | One per Disclosure; `@context`, `type` and `issuer` are never among them | A Key Binding JWT, as for `dc+sd-jwt` |
| `jpt` (DRAFT) | One per payload slot, named by the Issuer Header's `claims` | A Presentation Header with `aud` and `nonce`, signed by the holder (SU, MAC) or bound by the BBS proof itself |
| `sd-cwt` (DRAFT) | One per disclosure | A Key Binding Token by the `cnf` key, with `aud`, `cnonce` and `iat` |
| `vc+jwt`, `vc+cose` (W3C) | Every claim listed, none selectable | The credential as an `EnvelopedVerifiableCredential` inside a `vp+jwt` signed with the bound key, carrying the `nonce` and the Client Identifier as `aud` |

### Holder private key

The row appears when the key is not found in storage. Its note says one of:

* *Using the key pasted here. It is not stored.*
* *Not in this browser's storage — paste the key pair you downloaded on
  issuance step 2.*
* *the pasted key is not the key this credential is bound to — its cnf.jwk
  names a different key, so a Key Binding JWT signed with it would be
  refused*
* a parse problem, such as *the pasted holder key is not JSON: ...*

When the key is in storage the row is hidden. The **Key Binding and DPoP**
pane then says which key signs, and explains why OpenID4VP has no DPoP.

### ldp_vc

The credential's `bbs-2023` proof is W3C Data Integrity BBS Cryptosuites
v1.0. A credential from an issuer that predates it (iya-sts before 1.1.0,
whose base proof is a bare BBS signature) cannot be presented, and the
status says so.

The page canonicalizes the credential before it can show rows. It uses only
the JSON-LD contexts it ships and any you add in **JSON-LD Contexts**: paste
the context URL exactly as the credential's `@context` names it, and the
document served there, then **Add Context**. Added contexts are kept in this
browser. A missing context shows as *This credential could not be
canonicalized, so no bbs-2023 proof can be derived from it: ...*.

When the query requires holder binding (DCQL's default), or an ID Token goes
with it, the derived credential is wrapped in a `VerifiablePresentation`
signed by the DID in `credentialSubject.id`. `/credentialSubject/id` is
then selected by default, because it names that DID. Signing needs the
private key of that DID. Without it the status says
*This request needs a holder proof around the ldp_vc presentation, and the
private key of `<did>` is not available ...*.

### mso_mdoc

The DeviceResponse carries the chosen elements exactly as issued, and the
issuer's signature unchanged. The device signature covers OpenID4VP's session
transcript: the `client_id`, the `nonce`, the response URI and, under
`direct_post.jwt`, the key the answer is encrypted to. The presentation pane
shows that transcript where a KB-JWT would be.

### The Presentation

`sd_hash`, the holder proof's header and payload, the signed proof, the
presentation itself, the `vp_token` (a JSON object keyed by the DCQL
credential query id, each value an array), and **What they will know**: the
claims that follow from those bytes.

### The Encrypted Response (direct_post.jwt)

Shown only for `direct_post.jwt`. **Content encryption** offers the
Verifier's `encrypted_response_enc_values_supported` that the wallet does,
A128GCM when the Verifier says nothing. The key is the first one in the
Verifier's `client_metadata.jwks` the wallet can use, in the Verifier's order,
and its `alg` decides the key management: ECDH-ES for a P-256 key (with no
`alg`, or `ECDH-ES`), or ML-KEM or HPKE for an AKP, EC or OKP key that names
one. A Verifier that lists an X-Wing (`HPKE-10-KE`) key before its P-256 one
therefore gets a post-quantum answer. Under HAIP only ECDH-ES P-256 is used.
For an mdoc the key also goes into the session transcript as an RFC 7638
thumbprint, and an AKP key has none, so it is passed over. An Integrated
`HPKE-n` key produces a JWE with no `enc`.
The pane shows the JWE header (with the Verifier key's `kid`) and the compact
JWE that is posted as the single form field `response`.

### Present It

**The call this will make** is the HTTP request Present sends. For an answer
the browser carries it starts *(the BROWSER submits this, as an auto-posting
form)*, or it is a `302` with the `Location`.

| `response_mode` | Who sends it | To |
|---|---|---|
| `direct_post` | the wallet | `response_uri` |
| `direct_post.jwt` | the wallet, one field `response`, encrypted | `response_uri` |
| `post` (SIOPv2) | the wallet | `redirect_uri` |
| `form_post` | the browser, as an auto-submitting form | `redirect_uri` |
| `fragment` (default) / `query` | the browser, redirected | `redirect_uri` |

**Present** sends it. On a wallet POST the page says *The verifier accepted
the response. Opening step 3 …*, or *The verifier refused the response: ...
Step 3 shows what it answered.* and opens step 3 shortly after. On a
browser-carried answer the browser leaves for the Verifier and does not come
back; step 3 still shows what was sent, because it is recorded first.

**Refuse** declines. It sends `access_denied` for a presentation and SIOPv2's
`user_cancelled` for an ID Token alone, or `subject_syntax_types_not_supported`
when the wallet can make no subject the Verifier accepts. The refusal goes the
way an answer would, encrypted under `direct_post.jwt`. Nothing from the
credential leaves the browser.

## Sending through the api

A wallet in a browser page can use a Verifier only if it sends CORS headers.
Most do not, because a wallet is normally a native app. Tick **through the
api** on step 0 and every call the wallet makes to the Verifier goes through
the debugger's api, `POST /oid4vp/call`, which no browser policy applies to:

* the Request Object, by GET or by POST under `request_uri_method=post`;
* the Verifier's JWKS;
* every answer and refusal the wallet posts.

Answers the browser carries (`fragment`, `query`, `form_post`) always go
through the browser.

**check the Verifier's TLS certificate on that route** is on by default.
Clear it for a Verifier with a self-signed certificate.

The boxes are enabled only when the api answers `GET /oid4vp/limits`.
Otherwise they are disabled and the note says *This deployment has no api
answering at ..., so the wallet reaches the Verifier from the browser, which
needs the Verifier to send CORS headers.*

The api answers in three ways, and the page reports them differently:

| What happened | What the page says |
|---|---|
| The Verifier answered anything, including a refusal | The Verifier's own status and body, as if the page had called it |
| The api refused the call (its checks, or its address policy) | *the debugger's api refused the call: ...* |
| The Verifier could not be reached | *the debugger's api could not reach the Verifier: ...* |

The api forwards a body of at most 262144 bytes by default
(`oid4vpMaxRequestBytes`).

Step 3 says which route an answer took: **response_type / mode** ends in
*, through the debugger's api* when it went that way.

## Step 3: read the result

| Pane | What it shows |
|---|---|
| **What The Wallet Sent** | Who it went to, when, the holder proof, **What they can read**, and **Answered the request?**. The presentation is shown with its parts coloured. **Copy Presentation**, **Present Again** (back to step 2) and **Start Over** (discards the request, back to step 0). |
| **The Wallet's Own Checks** | The wallet re-checks the bytes it sent, as a Verifier would, OK or FAILED per check. |
| **How It Was Answered** | The protocol, `response_type / mode`, the holder binding, the ID Token, the JWE header and what was encrypted, with checks on them. |
| **What The Verifier Answered** | The Verifier's reply to the wallet's POST. |

**Answered the request?** compares the claims asked for with the claims sent,
by name:

* *Answered exactly: every claim asked for was disclosed, and nothing else.*
* *Answered — and N claim(s) went that were never asked for: ...*
* *NOT fully answered — withheld: ... It may well accept this anyway and say
  nothing.*

The wallet's own checks depend on the format. For `dc+sd-jwt` they include
**Key Binding JWT present**, **KB-JWT nonce**, **KB-JWT audience**,
**KB-JWT sd_hash** and **Disclosure digests**. For an mdoc they include
**Issuer signature**, **Element digests** and **Device signature**. If they
all pass the status says *The wallet's own checks on what it sent all pass.*

**What The Verifier Answered** is all OpenID4VP gives a wallet: a status and,
optionally, a `redirect_uri`. Which of its checks passed is the Verifier's
own record, and the wallet cannot read it. The status says *The Verifier
answered HTTP 200: it accepted the response.* or *The Verifier refused the
response: ...*. For an answer the browser carried it says the answer was
handed to the browser, so the Verifier spoke to the page it sent the browser
to, not to the wallet.

## SIOPv2

Choose **SIOPv2** on step 0. A request with `response_type=id_token` asks for
a self-issued ID Token alone. `response_type=vp_token id_token` asks for a
presentation with an ID Token beside it.

Step 2 shows **The Self-Issued ID Token (SIOPv2)**:

| Control | What it does |
|---|---|
| **Subject syntax** | A JWK Thumbprint (`urn:ietf:params:oauth:jwk-thumbprint`: `sub` is the RFC 7638 thumbprint, the key in `sub_jwk`), `did:jwk` or `did:key` (`sub` is the DID, named in the header's `kid`). Only syntaxes the Verifier lists in `subject_syntax_types_supported` are offered; when it lists none, the JWK Thumbprint. **The Verifier accepts:** shows its list. |
| **a pairwise key for this Verifier** | ID Token alone only. Off by default. A different key, and so a different `sub`, for each Verifier. Made the first time, reused for that Verifier after. |
| **keep pairwise keys in browser localStorage** | On by default. Cleared, the pairwise keys are deleted from storage at once, and a new key lasts only for that page load. |

The token is signed ES256. Its payload is `iss` equal to `sub`, `aud` the
Client Identifier, the request's `nonce`, `iat` and an `exp` five minutes
later.

Beside a presentation it is signed by the key the credential is bound to, so
the ID Token and the credential name one holder. Alone, it is signed by the
holder key, or a pairwise key when that box is ticked, or a pairwise key when
the wallet has no holder key.

A valid signature proves control of a key and nothing more. Every claim in a
self-issued ID Token is the holder's own.

Step 3's **How It Was Answered** checks **iss equals sub**, **ID Token aud**,
**ID Token nonce**, **ID Token signature**, **Subject is the key** for a JWK
Thumbprint subject, and **Same holder** when a presentation went with it.

## On the deployed static sites

The four pages ship to the static sites. Two things differ:

* No default Verifier is configured. **Restore Defaults** says *This
  deployment configures no default verifier (oid4vpVerifierUrlDefault is
  empty), so there is nothing to restore — enter the verifier by hand.*
  Enter the Verifier yourself, or paste a request into step 1.
* There is no api, so the api route is disabled with the note above. The
  wallet calls the Verifier from the browser, and only a Verifier that sends
  CORS headers can be used. Answers the browser carries work either way.

## Common errors

| What you see | What it means |
|---|---|
| *This request cannot be answered: ...* on step 1 | A REFUSED rule or a wallet problem. The rules pane shows which. |
| *Could not fetch the Request Object: the request_uri returned HTTP 404.* | The Verifier did not serve the Request Object, for example because the request expired. Start a new one. |
| *Could not fetch the Request Object: Failed to fetch* | Usually a Verifier that sends no CORS headers. Tick **through the api**. |
| *the debugger's api ...* with a TLS or connection error | The api could not reach the Verifier or did not trust its certificate. Clear the TLS box for a self-signed Verifier. If every api call fails in the browser, trust the stack's root, or accept the certificate on `https://localhost:4000` as well as on port 3000, as the README's *Running it* says. |
| *Nothing in that text looks like an OID4VP Authorization Request. ...* | The pasted text has no query string the wallet recognises. |
| *... asked for a `<format>` credential and this wallet holds a `<format>` one ...* | A presentation cannot change a credential's format. Issue the format asked for. |
| *... the private half of the holder key is missing, so no Key Binding JWT can be signed* | Saving was on and the key was never generated in this browser. Issue the credential again. |
| *this browser holds N key(s) but none of them is the one this credential is bound to ...* | The stored key is another one. A credential issued under Holder of Key needs the DPoP key, which is discarded when DPoP is switched off. |
| A `trust anchor` WARNING, and *FAILED trust anchor — no trust anchor is configured ...* under **Signature** | Paste the Verifier's root into **x509 trust anchor (PEM)** on step 0. |
| *Ready, but the selection is missing a claim the verifier asked for — it will refuse this.* | A requested row is not selected. |
| *The verifier refused the response: ...* | The Verifier's own answer. Step 3 shows it beside the wallet's checks. |
| *N of the wallet's own checks on what it sent FAIL — the verifier was right to refuse.* | The wallet could not verify its own presentation. |

iya-sts 1.0.0 cannot pass its own SIOPv2 same-holder check
(`id_token subject is the holder`) for an mdoc, whoever sends it. The
wallet's **Same holder** check passes for the same answer.

## What the browser keeps

The configuration, the protocol, the flow, the request in hand, the
selection and the record of what was sent are stored in `localStorage`. The
holder private key is stored only while **Save this holder key pair in
browser localStorage** is on in issuance. A pasted holder key is not stored.
Pairwise SIOPv2 keys are stored only while **keep pairwise keys in browser
localStorage** is on. Added JSON-LD contexts are kept in this browser.

## For developers

What the pages do internally, the storage keys, and how the test jobs drive
iya-sts, walt.id and Polaris are in
[The SD-JWT VC presentation workflow](sd-jwt-vc-presentation.md). Read it
before changing any `vc-presentation-*` page.
