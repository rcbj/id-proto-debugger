<!--
  Lead-generation report for idptools.com — the hosted, backendless deployment.
  Deliberately UNLINKED from the rest of docs/ (handed out on request, not
  published in the guide). Every feature below is defined by a published
  specification and works in the browser on the static site; drafts are marked
  as drafts. Last reviewed 2026-11-18.
-->

# Verifiable Credentials on idptools.com

### What the hosted debugger does, entirely in your browser

**idptools.com** is a free, hosted build of the identity-protocol debugger.
Its Verifiable Credential workflows let you act as a **wallet** — receiving
credentials from any OpenID4VCI issuer and presenting them to any OpenID4VP
verifier — against your own systems, with nothing to install. Every feature
in this report is defined by a **published specification**; nothing here is
proprietary to one product, and emerging drafts are labelled as drafts.

> **Standards at a glance:** OpenID4VCI 1.0 · OpenID4VP 1.0 · HAIP 1.0 ·
> SIOPv2 · SD-JWT VC · ISO mdoc · W3C VC Data Model 2.0 · AnonCreds · DPoP ·
> DCQL · Presentation Exchange · Token & Bitstring Status Lists.

---

## How the hosted site works — and what it will and will not do

idptools.com is served as **static content from a CDN. It runs no server of
its own and stores nothing.** Every credential you receive, every key you
generate, and every presentation you build lives only in your browser tab and
is gone when you close it. That is the point: there is no account, no upload,
and no server-side copy of anything sensitive.

One principle decides what is possible here. Anything that happens **in your
browser**, or talks to **your own systems**, works on the hosted site.
Anything that would need a server to **hold a message between two parties**,
**keep state**, or **store a credential** requires the self-hosted build (a
pair of containers you run yourself).

**You can, on idptools.com:**

- Receive credentials from **your** OpenID4VCI issuer and verify them.
- Build and sign OpenID4VP **presentations** of the credentials you hold.
- Answer a verifier through the browser's **Digital Credentials API**.
- Inspect, decode and verify every artifact involved — all offline.

**You will need the self-hosted build for:**

- Running the debugger as a **hosted Verifier** (serving a `request_uri` and
  receiving a wallet's `direct_post` answer) — because that would mean holding
  a presented credential on a server, which the hosted site deliberately never
  does.
- Reaching a remote party that sends **no CORS headers**, where the call must
  be proxied server-side.

> **Reaching your issuer or verifier.** The pages fetch the other party's
> metadata and requests directly from the browser, so that party needs to
> send CORS headers naming `https://idptools.com`. Where it cannot, you can
> upload its metadata from a file, or run the self-hosted build, which proxies
> the call for you.

---

## As a wallet receiving credentials — OpenID4VCI 1.0

The debugger implements the **OpenID for Verifiable Credential Issuance 1.0**
flow end to end, and shows every message as it is sent and received.

**Reasonable defaults.** Out of the box it acts as a **public client** (no
client secret), requests an **`dc+sd-jwt`** (SD-JWT VC) credential, and reads
everything it needs from the issuer's published metadata.

| Capability | Specification |
|---|---|
| **Pre-authorized code** flow, including a **Transaction Code** | OpenID4VCI 1.0 §6.1, Appendix H.2 |
| **Authorization Code** flow with **PKCE** | §5; RFC 6749; RFC 7636 |
| **Credential Offer** by value, by reference (`credential_offer_uri`), or scanned from a **QR code** | §4.1, Appendix H |
| **Issuer and authorization-server metadata** discovery, with signed-metadata validation | §12.2, §12.2.3; RFC 8414 |
| **Nonce Endpoint** and the holder **key proof** (`openid4vci-proof+jwt`) | §7, §8 |
| **Selective claim requests** via `authorization_details` | §5.1.1; RFC 9396 |
| **DPoP** sender-constrained tokens, with optional holder-of-key binding | RFC 9449 |
| **Deferred** issuance (credential not ready yet) | §9, Appendix H.3 |
| **Refresh** and re-issuance, with a full credential history | §14.5; RFC 6749 §6 |
| **Credential verification**: issuer signature, disclosure digests, holder binding | §8.3 |
| **Notification Endpoint** (`credential_accepted` / `_deleted` / `_failure`) | §11 |

**Client authentication** at the token endpoint — selectable, defaulting to a
public client:

| Method | Specification |
|---|---|
| `none` (public client, default) | RFC 6749 |
| `client_secret_basic`, `client_secret_post` | RFC 6749 §2.3.1 |
| `client_secret_jwt` | RFC 7523 §2.2 |
| `private_key_jwt` | RFC 7523 |

Secrets you type are used for that page only and are **never stored**.

---

## As a wallet presenting credentials — OpenID4VP 1.0

The debugger answers any **OpenID for Verifiable Presentations 1.0** request,
building and signing the presentation from a credential it holds.

**Reasonable defaults.** It presents an **SD-JWT VC**, discloses only the
claims the request asks for, and binds the presentation to the request's
**`nonce`**. The response mode is the one the verifier's request specifies; on
the hosted site the **Digital Credentials API** path returns the answer
entirely in-browser, while an HTTP `direct_post` to a remote verifier needs
that verifier's CORS headers (or the self-hosted build).

| Capability | Specification |
|---|---|
| **DCQL** — the Digital Credentials Query Language | OpenID4VP 1.0 §6 |
| **Presentation Exchange** query (the earlier mechanism) | DIF Presentation Exchange 2.1.1 |
| Request **by value**, or **by reference** (`request_uri`, signed Request Object) | §5, §5.7; RFC 9101 |
| **Client Identifier prefixes** — how the wallet authenticates the verifier | §5.9 |
| Response mode **`direct_post`** | §8.2 |
| Response mode **`direct_post.jwt`** — the answer encrypted as a JWE (ECDH-ES, P-256) | §8.3 |
| The browser **Digital Credentials API** (`dc_api`, `dc_api.jwt`) | Appendix A |
| **Selective disclosure** of SD-JWT VC claims, with a Key Binding JWT | RFC 9901 §4.3 |
| **Predicate** proofs — e.g. "age ≥ 18" without revealing the value | DIF PE 2.1.1 Predicate Feature; AnonCreds |
| **Transaction data** binding (`transaction_data`) | §8.4 |
| **Credential status** checks (see below) | per mechanism |

**HAIP 1.0** and **SIOPv2** are offered as first-class modes:

| Mode | What it adds | Specification |
|---|---|---|
| **HAIP 1.0** | The high-assurance profile: one way to authenticate the request and one way to protect the answer, no negotiation | OpenID4VC High Assurance Interoperability Profile 1.0 |
| **SIOPv2** | A self-issued **ID Token** signed by the wallet's own key, returned alongside the presentation | Self-Issued OpenID Provider v2 |

---

## Credential formats

The wallet receives, verifies and presents every format below.

| Format | Binding | Specification |
|---|---|---|
| **SD-JWT VC** (`dc+sd-jwt`) | `cnf.jwk` | SD-JWT VC; SD-JWT (RFC 9901) |
| `jwt_vc_json` | `cnf.jwk` | W3C VC Data Model 2.0 |
| `ldp_vc` (Data Integrity) | `credentialSubject.id` (`did:jwk`) | W3C VC Data Model 2.0; W3C Data Integrity |
| **ISO mdoc** (`mso_mdoc`) | device key in the MSO | ISO/IEC 18013-5 |
| `vc+jwt`, `vc+sd-jwt`, `vc+cose` | `cnf` | W3C VC-JOSE-COSE |
| **AnonCreds** | a link secret | AnonCreds Specification |

**Credential status** is checked per family:

| Mechanism | Specification | Formats |
|---|---|---|
| **Bitstring Status List** | W3C Bitstring Status List v1.0 | `jwt_vc_json`, `ldp_vc` |
| **Token Status List** | draft-ietf-oauth-status-list (IETF, **a draft**) | `dc+sd-jwt`, `mso_mdoc` |
| **AnonCreds revocation** | AnonCreds (zero-knowledge) | `anoncreds` |

**Emerging drafts**, implemented and clearly marked as drafts: JSON Web Proofs
(`jpt`), SD-CWT (`sd-cwt`), and post-quantum / HPKE encryption of the
`direct_post.jwt` answer.

---

## Offline tools (always available, nothing leaves the browser)

Decode and verify every artifact the workflows produce — SD-JWT VCs and their
disclosures, JWTs and JWS, X.509 chains and keys, DIDs and `did:web` domain
linkage, VC Barcodes, Gordian Envelopes and ACDCs — with no network call and
nothing stored.

---

## Beyond the hosted site

The same build, run as a pair of containers you host yourself, adds the
server-dependent roles the static site deliberately leaves out: the debugger
acting as a **hosted OpenID4VP Verifier** (serving the `request_uri` and
receiving a wallet's `direct_post` answer, with every check shown one row at a
time), server-side proxying to parties without CORS, and the non-browser
protocol workflows (Kerberos, LDAP, SPIFFE and more).

---

## Appendix — a reference setup with iya-sts

> **iya-sts is one example, not a requirement.** idptools.com works with
> **any** OpenID4VCI issuer and OpenID4VP verifier. iya-sts is the open
> reference server the debugger is tested against; the steps below stand one
> up and point the hosted wallet at it. Every feature configured is
> spec-defined. Written against iya-sts **1.1.0**; its
> `GET /admin-api/openapi.json` is the authority for another release.

### What idptools.com needs from the server

Because the hosted site runs entirely in your browser, the server must be
reachable **from the browser**:

- a public **HTTPS** origin with a **browser-trusted certificate**;
- **CORS** headers naming `https://idptools.com`;
- for the Authorization Code flow, a client whose redirect URI is
  `https://idptools.com/callback`.

### 1. Run iya-sts out of the box

The published image serves the OpenID4VCI issuer and the OpenID4VP verifier on
one HTTPS port (8081 inside the container). Its default service hostnames
include **`sts.example.com`**, used as the domain throughout; point that name
at the host with a trusted certificate, or substitute your own domain.

```bash
docker run -d --name iya-sts -p 443:8081 \
  -e STS_MODE=product \
  -e ADMIN_API_CLIENT_SECRET="<choose a strong secret>" \
  -e STS_TLS_CERT_FILE=/tls/fullchain.pem \
  -e STS_TLS_KEY_FILE=/tls/privkey.pem \
  -v /path/to/tls:/tls:ro \
  ghcr.io/rcbj/iya-sts:<version>
```

(TLS files are optional — the image self-signs when they are unset — but a
public, browser-reachable instance needs a trusted certificate.) Out of the
box it runs in **product mode** (it serves only clients and people registered
ahead of time) and advertises five **spec** credential configurations:

| Configuration id | Format | Scope |
|---|---|---|
| `IdentityCredential` | `dc+sd-jwt` (SD-JWT VC) | `identity_credential` |
| `IdentityCredentialJwtVcJson` | `jwt_vc_json` | `identity_credential_jwt` |
| `IdentityCredentialLdpVc` | `ldp_vc` | `identity_credential_ldp` |
| `IdentityCredentialDid` | `dc+sd-jwt`, issuer `did:web` | `identity_credential_did` |
| `IdentityCredentialLdpVcDid` | `ldp_vc`, issuer `did:web` | `identity_credential_ldp_did` |

Set the public origin and allow the hosted site (through the management API,
below, or the equivalent `/admin` console pages):

```text
POST /admin-api/config/set  { "key": "global.publicBaseUrl",
                              "value": "https://sts.example.com" }
POST /admin-api/config/set  { "key": "global.corsOrigins",
                              "value": ["https://idptools.com"] }
```

### 2. A management-API token

`/admin-api` takes an OAuth 2.0 access token from the seeded `sts-api-client`
by `client_credentials`:

```bash
curl -s https://sts.example.com/oauth2/token \
  -u 'sts-api-client:<the ADMIN_API_CLIENT_SECRET you set>' \
  -d grant_type=client_credentials \
  -d 'scope=admin:read admin:write' \
  -d resource=https://sts.example.com/admin-api
```

Send the returned token as `Authorization: Bearer <token>` on every call
below. Keep the secret out of files, pages and screenshots.

### 3. A holder account

```text
POST /admin-api/users/create
{ "username": "demo-holder", "invent": false, "credential": "password",
  "password": "<meets the realm's policy>",
  "attributes": { "cn": "Demo Holder", "givenName": "Demo",
                  "sn": "Holder", "mail": "demo-holder@example.test" } }
```

The claims the issuer puts in a credential come from these directory
attributes; `GET /admin-api/users/new` lists the ones it accepts.

### 4. A wallet client for idptools.com

A public client whose redirect URI is the hosted site's `/callback`:

```text
POST /admin-api/applications/create
{ "identifier": "idptools-wallet",
  "protocols": ["oauth2", "oidc", "oid4vci"],
  "fields": {
    "oauthClientId": "idptools-wallet",
    "oauthGrantType": ["authorization_code", "refresh_token",
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"],
    "oauthRedirectUri": ["https://idptools.com/callback"],
    "oauthResponseType": ["code"],
    "oauthTokenEndpointAuthMethod": "none",
    "oauthAllowedScope": ["openid", "offline_access",
      "identity_credential", "identity_credential_jwt",
      "identity_credential_ldp", "identity_credential_did",
      "identity_credential_ldp_did"] } }
```

`oidc` is declared because an `openid` scope has the issuer mint an ID token;
`oauthAllowedScope` lists the credential scopes from the issuer metadata.

### 5. Point idptools.com at it

**VC Issuance.** On step 1, set the **Credential Issuer Metadata URL** to
`https://sts.example.com/.well-known/openid-credential-issuer` and **client_id**
to `idptools-wallet`. Choose a configuration (e.g. `IdentityCredential`) and
**Start Issuance** for the Authorization Code flow; or make a **pre-authorized**
offer at `https://sts.example.com/portal/wallet` signed in as `demo-holder`,
and paste it into step 1.

**VC Presentation.** Present to iya-sts's verifier, or in-browser through the
**Digital Credentials API**. The hosted site cannot run the debugger's **own**
hosted Verifier — that would store a presented credential server-side — so use
the self-hosted build for that role.

### 6. Remove it again

```text
POST /admin-api/users/delete         { "user": "demo-holder" }
POST /admin-api/applications/forget  { "application": "idptools-wallet" }
POST /admin-api/config/reset         { "key": "global.corsOrigins" }
POST /admin-api/config/reset         { "key": "global.publicBaseUrl" }
```

---

*Every capability in this report is defined by a published specification.
Reviewed 2026-11-18.*
