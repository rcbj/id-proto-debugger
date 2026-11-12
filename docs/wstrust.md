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
