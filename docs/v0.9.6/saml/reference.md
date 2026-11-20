---
title: "SAML workflow — configuration reference"
---

# SAML workflow — configuration reference

Every pane, field and button on `saml_request.html` and
`saml_response.html`. For each control: the element id, what it does,
which specification defines it, its default, and whether it is stored.

The order to use them in is the [tutorials](tutorials.md). Why the two
protocol versions differ is [SAML 1.1](../saml11.md).

Unless a row says otherwise, **Stored** means `localStorage` under
`samltools_` plus the element id. A fresh page shows the HTML
placeholder until you load metadata or until a stored value is
restored.

* TOC
{:toc}

## IdP Metadata (`saml_request.html`)

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Metadata Document URL | `saml_metadata_url` | Where **Load Metadata** fetches the identity provider's `EntityDescriptor` (Metadata, section 2). With a backend the fetch is `GET /samlmetadata` on the api. | Empty, then the Keycloak URL `http://localhost:8080/realms/debugger-testing/protocol/saml/descriptor` once the page has run. | Yes |
| Load Metadata | | Fetches that URL and fills Configuration Parameters. | | |
| Upload Metadata | | Parses a local `.xml` file. No fetch. | | |
| Metadata Document | `saml_metadata_doc` | The raw XML, read-only, with **Copy**. | Empty | Yes |
| Metadata status | `saml_metadata_status` | `Loaded and parsed.` or the error. An expired `validUntil` is reported and the document is still shown. | | Not stored |

## Configuration Parameters

These are what a fresh page shows. **Load Metadata** replaces them
with the identity provider's.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| IdP entityID | `saml_idp_entity_id` | The identity provider's entityID (Metadata, section 2.2.1). | `http://localhost:8080/samlp/metadata` | Yes |
| HTTP-POST binding URL | `saml_sso_post` | `SingleSignOnService` for HTTP-POST (Bindings, section 3.5). | `http://localhost:8080/samlp/sso/post` | Yes |
| HTTP-Redirect binding URL | `saml_sso_redirect` | `SingleSignOnService` for HTTP-Redirect (Bindings, section 3.4). | `http://localhost:8080/samlp/sso/redirect` | Yes |
| HTTP-Artifact binding URL | `saml_sso_artifact` | Advertised artifact SSO endpoint. Not used as the destination of an artifact *response*. | `http://localhost:8080/samlp/sso/artifact` | Yes |
| Artifact Resolution Service | `saml_ars` | SOAP endpoint the api calls to resolve an artifact (Bindings, section 3.6). | `http://localhost:8080/samlp/ars` | Yes |
| HTTP-POST logout URL | `saml_slo_post` | `SingleLogoutService` for HTTP-POST. Hidden on SAML 1.1. | `http://localhost:8080/samlp/slo/post` | Yes |
| HTTP-Redirect logout URL | `saml_slo_redirect` | `SingleLogoutService` for HTTP-Redirect. | `http://localhost:8080/samlp/slo/redirect` | Yes |
| HTTP-Artifact logout URL | `saml_slo_artifact` | Advertised artifact logout endpoint. | `http://localhost:8080/samlp/slo/artifact` | Yes |
| Supported NameIDFormat | `saml_nameid_format` | `NameIDPolicy` format, filled from the metadata. Empty until a document is loaded. | Empty | Yes |
| Signer Certificate | `saml_signer_cert` | Identity-provider signing certificate. **Load Metadata** replaces the sample. **View signer certificate details** opens [Certificate Details](../saml-decoders.md#certificate-details). | A sample certificate, subject `saml-debugger-sp-test` | Yes |

## SP / Request Settings

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Protocol Version | `saml_version` | SAML 2.0, SAML 1.1, or SAML 1.0 (reference only). Changing it greys out settings that version does not have. | SAML 2.0 | Yes |
| Version warning | `saml_version_warning` | Shown when the version is not 2.0. | Hidden | Not stored |
| Request binding | `saml_binding` | How the request travels: HTTP-Redirect or HTTP-POST. No artifact option. Greyed on SAML 1.1. | HTTP-Redirect | Yes |
| Response binding | `saml_response_binding` | `ProtocolBinding`: HTTP-POST or HTTP-Artifact. Independent of the request binding. | HTTP-POST | Yes |
| Username hint | `saml_username_hint` | Optional subject hint. The selected NameID format constrains it. Greyed on SAML 1.1. | Empty | Yes |
| SP entityID | `saml_sp_entity_id` | Issuer of the AuthnRequest. | `https://localhost:3000/saml/sp` when the field was empty, from the client config `spEntityId` | Yes |
| ACS URL | `saml_acs_url` | Assertion consumer. The local default is the api. A static site uses its edge URL. | `https://localhost:4000/samlacs` when empty, from `acsUrl` | Yes |
| Artifact ACS URL (SAML 1.1) | `saml11_artifact_acs_url` | The Browser/Artifact consumer. Shown only for SAML 1.1. Sent as `shire` when the response binding is artifact. | Derived from the ACS | Yes |
| Digitally sign the AuthnRequest | `saml_sign_request` | Signs with the key pair below. Clearing it hides those fields. On SAML 1.1 the checkbox is disabled. The key still signs artifact SOAP. | On | Yes |
| Signature Algorithm | `saml_sig_alg` | `SignatureMethod`. RSA-SHA256, RSA-SHA1, RSA-SHA384, RSA-SHA512. On load, the draft post-quantum group is appended. See [Post-quantum XML Signature](../xmldsig-pqc.md). | RSA-SHA256 | Yes |
| Key Size | `saml_key_bits` | RSA modulus for **Generate Keys**. | 2048. Also 3072 and 4096. | Yes |
| Generate Keys | | A fresh RSA pair and a self-signed certificate. | | |
| Download | | The pair as PEM. | | |
| Private Signer Key | `saml_sp_private_key` | PKCS#8 PEM. Signs the AuthnRequest. | Empty | Key material. Written only while **Save this key pair** is checked (`samltools_saml_save_keypair`). Clearing the box removes it. |
| Public Signer Certificate | `saml_sp_public_key` | The certificate to register at the identity provider. | Empty | Same checkbox as the private key |
| Save this key pair in browser localStorage | `saml_save_keypair` | On by default. The response page needs the private key to decrypt an encrypted assertion. With saving off, use **Download** and paste the key into **Decryption Key**. | On | The preference itself is stored |
| Encrypt the AuthnRequest | `saml_encrypt_request` | XML Encryption of the request, in the browser, after the signature. Off, and greyed on SAML 1.1. Most identity providers do not accept an encrypted AuthnRequest. | Off | Yes |
| Encryption Certificate | `saml_enc_cert` | Identity-provider certificate that wraps the session key. | Empty until metadata is loaded | Yes |
| Encrypted Type | `saml_enc_type` | Element (the whole AuthnRequest) or Content. | Element | Yes |
| Canonicalization | `saml_enc_c14n` | How the plaintext is serialized before encryption. | None (serialize as-is). Also exclusive and inclusive C14N 1.0. | Yes |
| Data Encryption Algorithm | `saml_enc_data_alg` | AES-GCM at 256, 192 and 128, AES-CBC at those sizes, Triple DES CBC. | AES-256-GCM | Yes |
| Key Transport Algorithm | `saml_enc_key_alg` | RSA-OAEP (XML Encryption 1.1), RSA-OAEP-MGF1P, RSA-1_5. | RSA-OAEP (xmlenc11) | Yes |
| Key Transport Digest | `saml_enc_digest` | OAEP digest. | SHA-256. Also SHA-1, SHA-384, SHA-512. | Yes |
| MGF | `saml_enc_mgf` | Mask generation for RSA-OAEP (XML Encryption 1.1). | MGF1 with SHA-256 | Yes |
| Add WS-Addressing headers | `saml_wsa_support` | SOAP headers on the artifact-resolution call only. They do not change a redirect or a POST AuthnRequest. | Off | Yes |
| wsa:To | `saml_wsa_to` | Defaults to the artifact resolution URL when blank. | Empty | Yes |
| wsa:Action | `saml_wsa_action` | | Empty | Yes |
| wsa:ReplyTo | `saml_wsa_replyto` | | Placeholder `http://www.w3.org/2005/08/addressing/anonymous` | Yes |
| wsa:From | `saml_wsa_from` | | Empty | Yes |
| wsa:MessageID | `saml_wsa_messageid` | A `urn:uuid:` value when blank. | Empty | Yes |
| Generated AuthnRequest | `saml_authn_request` | Rebuilt as you edit. Read-only. For the redirect binding this is the signed request URL. On SAML 1.1 it is the inter-site transfer URL. There is no request document. | | Not stored |
| Call IdP | | Signs, when signing is on, and sends the request to the SSO URL for the request binding. | | |
| Logout | `saml_logout_btn` | A signed `LogoutRequest` for the last session. Needs `saml_last_nameid` and a single-logout URL. Unavailable on SAML 1.1. | | |
| Download SP Metadata | | This service provider's `EntityDescriptor`, to register at the identity provider. SAML 2.0 metadata includes `SingleLogoutService` and `AuthnRequestsSigned`. SAML 1.1 metadata uses the profile URIs and has no logout service. | | |
| Call status | `saml_call_status` | Status of the last build or send. | | Not stored |

## The response page (`saml_response.html`)

The page opens when the api, or the static site's edge function, has
caught the response.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Status | `saml_resp_status` | Whether a response was loaded. | | Not stored |
| Response XML | `saml_resp_xml` | The `Response` or `LogoutResponse`. | | The exchange is passed from the api. `saml_last_response` keeps the last response (`localStorage`, class output). |
| Response details | `saml_resp_details` | Parsed status, issuer, and bindings. | | Not stored |
| Assertion XML | `saml_assertion_xml` | The assertion, after decryption when you decrypt. | | Not stored |
| Attributes | `saml_attrs_table` | Attribute statement as a table. | | Not stored |
| Verify with | `saml_sig_trust` | **The IdP's signing certificate(s)** or **KeyInfo** (integrity only). | The trusted certificates, when any were loaded | Not stored |
| Trusted certificates | `saml_trusted_certs` | PEM from the metadata loaded on the request page. Several certificates are separated by a blank line. | Filled from that metadata | Not stored |
| Validate Signatures | | Each enveloped signature on its own: the `Response` and the assertion. On SAML 1.1 Browser/POST it also says when the `Response` is unsigned, which that profile forbids. | | |
| Signature status | `saml_sig_status` | | | Not stored |
| Signature details | `saml_sig_details` | One row per signature. | | Not stored |
| Decryption Key | `saml_dec_key` | Recipient private key. Prefilled from the saved SP private key. | That key, when it was saved | Not stored. Paste it when saving was off. |
| Decrypt | | Opens an `EncryptedAssertion` or a message-level `EncryptedData`. | | |
| Decrypt status | `saml_dec_status` | | | Not stored |

### Decrypting an assertion

**Decryption Key** is the service-provider private key. iya-sts does
not encrypt a Web Browser SSO assertion, so a round trip against it
has nothing to decrypt. A provider that encrypts to the certificate
you registered, the stack's Keycloak included, returns ciphertext this
button opens.

## What else is kept

| Key | What it is |
|---|---|
| `saml_last_nameid` | NameID from the last assertion. **Logout** will not send without it. |
| `saml_last_nameid_format` | The format of that NameID. |
| `saml_last_session_index` | Session index, sent on the `LogoutRequest`. |
| `samltools_operation_history` | The operations log, shared by the request and response pages. **Clear History** drops it. |

There is no password field on this workflow. The password is typed on
the identity provider's own sign-in page and is not stored here.

The [SAML Assertion Tool](../saml-assertion.md) is a different page. It
stores `sa_private_key`, `sa_public_key`, and `sa_enc_private_key`, and
it has no save-keypair checkbox.
