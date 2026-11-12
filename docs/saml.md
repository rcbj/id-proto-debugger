---
title: "Using the SAML workflow"
---

# Using the SAML workflow

The SAML workflow is the **SAML Protocol** card on the landing page. It is
two pages. `saml_request.html` builds the request and sends it to an identity
provider. `saml_response.html` shows the response that came back to the
assertion consumer service.

**Protocol Version** defaults to **SAML 2.0**. SAML 1.1 is a different
exchange and has [its own page](saml11.md). **SAML 1.0 (reference only)**
fills the form and does not complete a sign-in.

These pages have no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## Before you start

From a checkout, follow *Getting Started* in the repository's
[README](../README.md#getting-started). Then open `https://localhost:3000`
and pick **SAML Protocol**.

The assertion consumer and the single logout endpoint are on the API service
(`https://localhost:4000`). A deployed static site has no API, so **Call
IdP** has nowhere to land the response.

## Point it at iya-sts

On a fresh browser the form is filled with Keycloak-shaped placeholders,
all `http://localhost:8080/samlp/...`. If **Metadata Document URL** is
empty, the page writes the local default, which is also Keycloak:

`http://localhost:8080/realms/debugger-testing/protocol/saml/descriptor`

**SP entityID** and **ACS URL** are filled the same way when they are empty:

| Field | Filled with |
|---|---|
| SP entityID | `https://localhost:3000/saml/sp` |
| ACS URL | `https://localhost:4000/samlacs` |

[iya-sts](https://rcbj.github.io/iya-sts/) answers SAML 2.0 at
`https://localhost:8081`. Put one of these in **Metadata Document URL** and
click **Load Metadata**:

* `https://localhost:8081/saml2/metadata` — one document for any service
  provider.
* `https://localhost:8081/saml2/metadata/app-<12 hex>` — the document for
  one service provider. The twelve hex characters are the start of the
  SHA-256 of the SP entityID. The test launchers use this form. iya-sts
  mints the document when you ask for it.

SAML 1.1 metadata is the same slug under
`https://localhost:8081/saml11/metadata/`.

iya-sts signs a person in with any username. The literal password
`invalid` is refused, so a failed sign-in stays reachable. Any other
password is accepted.

**Load Metadata** replaces the placeholder entityID, the SSO and SLO URLs,
the artifact resolution service, the NameID formats, and the signer
certificate with what that document says. **Upload Metadata** does the same
from a file, with no fetch.

## IdP Metadata

| Field or button | Default | What it does |
|---|---|---|
| **Metadata Document URL** | the Keycloak URL above, once the page has run | Where **Load Metadata** fetches the descriptor. |
| **Load Metadata** | | Fetches that URL and fills Configuration Parameters. |
| **Upload Metadata** | | Opens a file picker (`.xml`) and parses the file. |
| **Metadata Document** | empty | The raw XML, read-only, with **Copy**. |

## Configuration Parameters

These values are what a fresh page shows *before* you load metadata. After
**Load Metadata** they are the identity provider's.

| Field | Placeholder on a fresh page |
|---|---|
| **IdP entityID** | `http://localhost:8080/samlp/metadata` |
| **HTTP-POST binding URL** | `http://localhost:8080/samlp/sso/post` |
| **HTTP-Redirect (GET) binding URL** | `http://localhost:8080/samlp/sso/redirect` |
| **HTTP-Artifact binding URL** | `http://localhost:8080/samlp/sso/artifact`. The label says this URL is not needed for an artifact *response*. |
| **Artifact Resolution Service (SOAP)** | `http://localhost:8080/samlp/ars` |
| **HTTP-POST logout URL** | `http://localhost:8080/samlp/slo/post` |
| **HTTP-Redirect (GET) logout URL** | `http://localhost:8080/samlp/slo/redirect` |
| **HTTP-Artifact logout URL** | `http://localhost:8080/samlp/slo/artifact` |
| **Supported NameIDFormat** | filled from metadata. Empty until a document is loaded. |
| **Signer Certificate** | a sample certificate, subject `saml-debugger-sp-test`. **Load Metadata** replaces it with the IdP signing certificate. **View signer certificate details** opens [Certificate Details](saml-decoders.md#certificate-details). |

Single logout fields are hidden when the protocol version has no logout.
See [SAML 1.1](saml11.md).

## SP / Request Settings

| Field | Default | What it does |
|---|---|---|
| **Protocol Version** | SAML 2.0 | Also SAML 1.1 and SAML 1.0 (reference only). Changing it greys out the settings that version does not have. |
| **Request binding** | HTTP-Redirect (GET) | Or HTTP-POST. There is no artifact option for the request. |
| **Response binding (ProtocolBinding)** | HTTP-POST | Or HTTP-Artifact. This is how the response comes back, which is separate from how the request goes out. |
| **Username hint** | empty | Optional. The selected NameID format constrains what you may type. |
| **SP entityID** | `https://localhost:3000/saml/sp` | The Issuer of the AuthnRequest, when the field was empty. |
| **ACS URL** | `https://localhost:4000/samlacs` | Where the IdP posts the response, when the field was empty. |
| **Digitally sign the AuthnRequest** | on | Hides the key-pair fields when you clear it. |
| **Signature Algorithm** | RSA-SHA256 | Also RSA-SHA1, RSA-SHA384, RSA-SHA512. After the page loads, a further group is added: **Post-quantum — draft-eastlake-rfc9231bis-xmlsec-uris**. Those sixteen methods are described in [Post-quantum XML Signature](xmldsig-pqc.md). |
| **Key Size** | 2048 | Also 3072 and 4096, for a generated RSA pair. |
| **Generate Keys** | | A fresh RSA pair and a self-signed SP certificate. |
| **Download** | | The pair as PEM. |
| **Private Signer Key** / **Public Signer Certificate** | empty | PKCS#8 PEM and the certificate. Register the certificate at the IdP if it checks the request signature. |
| **Save this key pair in browser localStorage** | on | Clearing it removes the pair already stored. The response page needs the private key to decrypt an encrypted assertion. With saving off, use **Download** and paste the key into **Decryption Key** on the response page. |
| **Encrypt the AuthnRequest** | off | The note on the form says Keycloak and most IdPs do not accept an encrypted AuthnRequest. Encryption runs in the browser, after the signature. |
| **Encryption Certificate** | empty until metadata is loaded | The IdP certificate that wraps the session key. |
| **Encrypted Type** | Element (whole AuthnRequest) | Or Content (children only). |
| **Canonicalization** | None (serialize as-is) | Or exclusive or inclusive C14N 1.0. |
| **Data Encryption Algorithm** | AES-256-GCM | Also AES-192-GCM, AES-128-GCM, AES-256/192/128-CBC, Triple DES CBC. |
| **Key Transport Algorithm** | RSA-OAEP (xmlenc11) | Also RSA-OAEP-MGF1P and RSA-1_5. |
| **Key Transport Digest (OAEP)** | SHA-256 | Also SHA-1, SHA-384, SHA-512. |
| **MGF (RSA-OAEP xmlenc11)** | MGF1 with SHA-256 | Also SHA-1, SHA-384, SHA-512. |
| **Add WS-Addressing headers** | off | SOAP headers on the artifact-resolution call only. They do not change a redirect or POST AuthnRequest. |
| **wsa:To** | the artifact resolution URL, if blank | |
| **wsa:Action** | empty | |
| **wsa:ReplyTo** | placeholder `http://www.w3.org/2005/08/addressing/anonymous` | |
| **wsa:From** | empty | |
| **wsa:MessageID** | a `urn:uuid:` value if blank | |
| **Generated AuthnRequest** | rebuilt as you edit | Read-only. **Copy** is on the label. For the redirect binding this is the signed request URL. |

**Call IdP** signs the request (when signing is on) and sends it to the SSO
URL for the request binding you chose.

**Logout** builds a signed LogoutRequest for the last session. It is
unavailable for SAML 1.1.

**Download SP Metadata** saves this service provider's EntityDescriptor, to
register at the identity provider.

## The response page

`saml_response.html` opens when the API has caught the response.

| Pane | What you do there |
|---|---|
| **SAMLResponse** | **XML** is the full response. **Details** is the parsed status and the bindings. |
| **Assertion (extracted)** | **XML** and **Attributes**. **Validate Signature** checks the enveloped signature with the certificate in `KeyInfo`. **Decrypt** uses **Decryption Key**, prefilled from the SP private key when that key was saved. |
| **Tools** | Request decoder, response decoder, assertion tool, certificate details, and the PKI page. See [SAML decoders](saml-decoders.md) and [SAML Assertion Tool](saml-assertion.md). |
| **Operations History** | The same log as the request page. **Clear History** drops it. A response turns the matching *Sent* row into *Success* or *Failure* from the status code. |

## What the browser keeps

Endpoints, the entityIDs, the bindings, and the certificates are stored in
`localStorage`. The SP private key is stored only while **Save this key pair
in browser localStorage** is checked. There is no password field on this
workflow.
