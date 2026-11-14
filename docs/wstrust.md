---
title: "Using the WS-Trust workflow"
---

# Using the WS-Trust workflow

The **WS-Trust Protocol** card opens `wstrust_tools.html`. The page builds a
SOAP `RequestSecurityToken` in the browser and sends it to a security token
service. The answer is shown on `wstrust_response.html`.

The request covers WS-Trust 1.0 through 1.4. The version selector defaults
to **1.4**.

These pages have no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## Before you start

From a checkout, follow *Getting Started* in the repository's
[README](../README.md#getting-started). Then open `https://localhost:3000`
and pick **WS-Trust Protocol**.

**Initiate STS Call From** defaults to **Backend (proxy)**, which is
`POST /wstrust` on the API. A SOAP service rarely allows a browser origin,
so leave it there unless you are testing CORS. On a deployed static site
the backend choice is disabled. **Frontend (browser)** calls the STS URL
directly.

## Point it at iya-sts

**STS URL** is empty in the HTML. When it is still empty, the page writes
`https://localhost:8081/sts`. That is
[iya-sts](https://rcbj.github.io/iya-sts/). The field's tooltip still
shows an `http://` example; the value the page fills in is `https`.

iya-sts accepts a UsernameToken of `wstrust` / `wstrust`, which is what the
username and password fields contain. The password is not written to
`localStorage`. The note under the password field says so.

**Validate STS TLS certificate (backend)** is on. Clear it when the STS
certificate is one this API does not trust.

## Request

| Field | Default | What it does |
|---|---|---|
| **SOAP Version** | SOAP 1.2 | Or SOAP 1.1. 1.2 sends `application/soap+xml` with the action in the content type. 1.1 sends `text/xml` and a `SOAPAction` header. |
| **WS-Trust Version** | 1.4 | 1.0 uses `.../ws/2004/04/trust`. 1.1 and 1.2 use `.../ws/2005/02/trust`. 1.3 and 1.4 use `.../ws-sx/ws-trust/200512`. **Bearer** is offered from 1.3. **ActAs** is offered on 1.4. Other versions hide those controls. |
| **Operation** | Issue | Also Renew, Validate, Cancel. |
| **Token Type** | SAML 2.0 | Also SAML 1.1, JWT, UsernameToken, Status. |
| **Key Type** | Bearer | Also SymmetricKey and PublicKey. |
| **Key Size (symmetric)** | 256 | Sent only for SymmetricKey. |
| **AppliesTo (RP endpoint)** | `urn:wstrust:test:rp` | `wsp:AppliesTo`. |
| **Lifetime (minutes)** | 60 | `0` omits `wst:Lifetime`. |
| **Requested Claims** | name, emailaddress, givenname, surname (the `.../ws/2005/05/identity/claims/` URIs, one per line) | Optional. One URI per line, or comma-separated. |
| **OnBehalfOf (delegation)** | off | Pastes a token into `wst:OnBehalfOf`. |
| **ActAs (WS-Trust 1.4)** | off | Pastes a token into `wst14:ActAs`. Hidden below version 1.4. |
| **Target Token** | empty | Required for Renew, Validate, and Cancel. Paste the token from an earlier Issue. It becomes `wst:RenewTarget`, `wst:ValidateTarget`, or `wst:CancelTarget`. |

## Credentials / WS-Security

| Field | Default | What it does |
|---|---|---|
| **Add wsu:Timestamp** | on | A timestamp in the security header. |
| **Credential** | UsernameToken | Also **SAML token** or **None**. |
| **Username** | `wstrust` | Stored. |
| **Password** | `wstrust` | Shown in the field. Not stored. |
| **Password Type** | PasswordText | Or PasswordDigest, which sends `Base64(SHA1(nonce + created + password))`. |
| **Import from SAML workflow** | | Copies the assertion from the last SAML response into **SAML assertion**. Shown when the credential is a SAML token. |

## Message protection

| Field | Default | What it does |
|---|---|---|
| **Digitally sign the request** | off | A WS-Security signature over the SOAP body. |
| **Also sign the Timestamp** | on, once signing is open | Adds the timestamp to the signed references. |
| **Signature Algorithm** | RSA-SHA256 | Also RSA-SHA1, RSA-SHA384, RSA-SHA512. After load, the same post-quantum group as the SAML page is appended. See [Post-quantum XML Signature](xmldsig-pqc.md). |
| **Key Size** | 2048 | Also 3072 and 4096. |
| **Generate Keys** / **Download** | | RSA pair and self-signed certificate, as PEM. |
| **Private Key** / **Certificate** | empty | PKCS#8 and the certificate carried in `KeyInfo`. |
| **Save this key pair in browser localStorage** | on | Clearing it removes the stored pair. The response page uses the private key to decrypt an encrypted token. The STS certificate in **Encryption Certificate** is left in storage either way. |
| **Encrypt the request body** | off | The note says most STSes will not process an encrypted body. Encryption is after the signature. |
| **Encryption Certificate** | empty | The STS certificate that wraps the session key. |
| **Encrypted Type** | Element (whole RST) | Or Content. |
| **Canonicalization** | None (serialize as-is) | Or exclusive or inclusive C14N 1.0. |
| **Data Encryption Algorithm** | AES-256-GCM | Also the 192 and 128 GCM sizes, AES-CBC at 256/192/128, and Triple DES CBC. |
| **Key Transport Algorithm** | RSA-OAEP (xmlenc11) | Also RSA-OAEP-MGF1P and RSA-1_5. |
| **Key Transport Digest** | SHA-256 | Also SHA-1, SHA-384, SHA-512. |
| **MGF** | MGF1 with SHA-256 | Also SHA-1, SHA-384, SHA-512. |

## WS-Addressing

**Add WS-Addressing headers** is on.

| Field | When it is blank |
|---|---|
| **wsa:Action** | Derived from the operation (Issue, Renew, Validate, Cancel). Edit it to override. |
| **wsa:To** | The STS URL. |
| **wsa:MessageID** | A `urn:uuid:` value. |
| **wsa:ReplyTo** | The anonymous URI `http://www.w3.org/2005/08/addressing/anonymous`. |
| **wsa:From** | Omitted. |

## Send

**Generated Request** is the SOAP document, rebuilt as you edit. **Rebuild**
forces that. **Send Request** posts it and opens the response page.

**Initiate STS Call From** defaults to **Backend (proxy)**. **Validate STS
TLS certificate (backend)** defaults to on.

## The response page

`wstrust_response.html` shows the SOAP request, the full response, and a
**Fields** tab (operation, response action, token type, key type, lifetime,
AppliesTo, and the Validate or Cancel status). **Issued Token** is the
contents of `wst:RequestedSecurityToken`. **Validate Signature** checks an
enveloped signature with the certificate in `KeyInfo`. **Decrypt** uses the
requestor private key.

## Operations history

Every call is listed, newest first: time, version, operation, username, and
a result of *Failure*, *Sent*, or *Success*. **Clear History** drops the
log. The log is kept in `localStorage`.

## WS-Trust test tools and the mock STS

The **WS-Trust Protocol** card opens `wstrust_tools.html`. The page builds
a SOAP `RequestSecurityToken` and shows the response on
`wstrust_response.html`.

**WS-Trust Version** defaults to 1.4. **SOAP Version** defaults to 1.2.
**Operation** defaults to Issue, **Token Type** to SAML 2.0, and **Key
Type** to Bearer. **STS URL** is empty in the form; while it stays empty
the page fills `https://localhost:8081/sts` (iya-sts). The tooltip on that
field still shows an `http://` example.

**Username** and **Password** default to `wstrust` / `wstrust`. The
password is not stored. **Digitally sign the request** defaults to off.
**Save this key pair in browser localStorage** defaults to on. **Encrypt
the request body** defaults to off. **Add WS-Addressing headers**
defaults to on.
**Initiate STS Call From** defaults to **Backend (proxy)**. **Validate STS
TLS certificate (backend)** defaults to on. On load the signature menu
gains the draft post-quantum group.

The field list is in [Using the WS-Trust workflow](wstrust.md).

### Mock authorization server
The same `sts/` service also answers **every endpoint its RFC 8414 metadata advertises**, so the OAuth2 / OIDC panes have a complete server to talk to without an identity provider:

| Endpoint | What it does |
|---|---|
| `GET /oauth2/authorize` | A browser flow: an unauthenticated request is answered with a **login screen**; once the user signs in it redirects back to itself and issues the authorization code (or the implicit / hybrid tokens), echoing `state` and identifying itself with `iss` (RFC 9207). Errors go where OAuth 2.0 says — back to the client when `redirect_uri` is usable, to the user agent when it is not. |
| `POST /oauth2/login` | The login screen's target. **No password is checked**: the username typed in is the identity every issued token then describes (`sub`, `username`, `preferred_username`, `given_name`, `email`). `login_hint` pre-fills the field, Cancel returns `access_denied`, an empty username re-prompts, and the password `invalid` is refused. A session cookie means later authorization requests do not prompt again; `prompt=login` forces a prompt, `prompt=none` fails with `login_required`, and `GET /oauth2/logout` ends the session. |
| `POST /oauth2/token` | `authorization_code` (verifying PKCE, single-use codes), `refresh_token`, `client_credentials`, `password`, and RFC 8693 `token-exchange`. Anything else is an `unsupported_grant_type`, and the metadata advertises exactly this list. |
| `POST /oauth2/introspect` | RFC 7662. Reports the real claims of a token it signed; anything forged, expired or revoked is `{"active": false}`. |
| `POST /oauth2/revoke` | RFC 7009. Always 200; a revoked token stops introspecting as active and stops refreshing. |
| `/oauth2/register` | RFC 7591 registration plus RFC 7592 read / update / delete, protected by the registration access token. |
| `GET /oauth2/jwks` | The signing key, so every token above can be verified. |
| `/docs`, `/policy`, `/tos` | The documents `service_documentation`, `op_policy_uri` and `op_tos_uri` link to. |

Every access, ID and refresh token is a real **RS256 JWT signed with the STS key** and verifiable against `jwks_uri`, with the claims OIDC asks for (`aud`, `nonce`, `at_hash`, `c_hash`). What it does **not** do is verify anything: no password is checked and any client secret or `redirect_uri` is accepted. The one credential it refuses is the password `invalid`, so a negative test has something to fail on.

Because it authenticates interactively, the debugger's own OAuth2 / OIDC workflow runs against it end to end with **no identity provider at all** — point the Metadata Retrieval pane at `/.well-known/oauth-authorization-server` (the default), Populate, and Authorize. The login screen deliberately uses the same field ids as the Keycloak login page (`username`, `password`, `kc-login`), so the Selenium helpers that drive one drive the other unchanged. The suite is `tests/oauth2_sts_endpoints.js` (no browser).

### What the mock records
The service logs with **bunyan**, at the level its `CONFIG_FILE` names (`sts/env/local.js` for the dev and live stacks, `sts/env/docker-tests.js` for the containerized suite — the same convention the api and client services use). At the default `debug` level the log is a complete account of what the mock did, which is what makes it useful when a test fails:

* **every endpoint call** — the path, the request headers and body, the response headers and body, the status code, and how long it took;
* **every security artifact both before and after it was protected** — a SAML assertion before signing and after, and again before and after encryption; a WS-Trust JWT, an OAuth access/ID/refresh token, an RFC 8414 or OID4VCI `signed_metadata` document, and an SD-JWT VC (its claims, its disclosures with salts and digests, the issuer-signed JWT, and the final Combined Serialization) — with the signed or encrypted object recorded in full;
* **entering and leaving** every function and every endpoint, on every path.

Set the level to `info` (`sts/env/test.js`) for a quiet run.

### STS for testing
The workflow is intended to run against [Apache CXF's WS-Trust STS](https://cxf.apache.org/docs/ws-trust.html). For the automated test suite it also runs against a small **WS-Trust STS mock** — [`rcbj/iya-sts`](https://github.com/rcbj/iya-sts), run from its release image (see *The mock STS runs from its release image* above) — that speaks the four operations (Issue mints a signed SAML 2.0 assertion or a JWT; Validate/Cancel return the corresponding status), accepts a `UsernameToken` of `wstrust`/`wstrust`, and sends permissive CORS headers. It runs as the `sts` service (port 8081) in the test/dev compose files, and the WS-Trust tests (`tests/wstrust.js`, one per operation plus a signed Issue) target it via `WSTRUST_STS_URL`. **That port is HTTPS in every stack here** (`STS_HTTPS=true`), because the RFC 9700 pass is a trust realm on the same instance rather than a second container and a realm binds no socket of its own — see `docs/rfc9700.md`; the compose files hand iya-sts the same leaf `./generate-tls-cert.sh` writes for the api and the client (`STS_TLS_CERT_FILE`), so one root covers all three. Without that file, iya-sts still issues its own certificate at every start. `trustStsCertificate()` in `common/common.sh` fetches `GET /tls/server-certificate` and installs that PEM as an anchor for node and as an exact key pin for Chrome. Against a **deployed static site** the same mock is started on the host and reached over loopback (`https://localhost:8081/sts`) so the browser can call it directly from the HTTPS page — a container/bridge hostname would not resolve in a browser off that network. There is no API proxy on that target, so those jobs are routed through the browser (frontend) and the backend-routing job is skipped; setting `WSTRUST_STS_URL` empty skips the WS-Trust jobs altogether rather than failing them.
