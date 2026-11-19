---
title: "WS-Trust workflow — configuration reference"
---

# WS-Trust workflow — configuration reference

Every pane, field and button on `wstrust_tools.html` and
`wstrust_response.html`. For each control: the element id, what it
does, which specification defines it, its default, and whether it is
stored.

The order to use them in is the [tutorials](tutorials.md).

Unless a row says otherwise, **Stored** means `localStorage` under
`wstrust_` plus the element id.

* TOC
{:toc}

## Endpoint

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| STS URL | `wst_sts_url` | The security token service. An empty field is filled from the client config. | `https://localhost:8081/sts` (`wstrustStsUrlDefault`). The tooltip example is `http://`. | Yes |
| SOAP Version | `wst_soap_version` | SOAP 1.2 sends `application/soap+xml` with the action in the content type. SOAP 1.1 sends `text/xml` and `SOAPAction`. | SOAP 1.2 | Yes |
| Endpoint status | `wst_sts_status` | | | Not stored |

## Request

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| WS-Trust Version | `wst_trust_version` | 1.0 uses `.../ws/2004/04/trust`. 1.1 and 1.2 use `.../ws/2005/02/trust`. 1.3 and 1.4 use `.../ws-sx/ws-trust/200512`. Bearer is offered from 1.3. ActAs is offered on 1.4. | 1.4 | Yes |
| Operation | `wst_operation` | `RequestType`: Issue, Renew, Validate, Cancel. | Issue | Yes |
| Token Type | `wst_token_type` | `wst:TokenType`. SAML 2.0, SAML 1.1, JWT, UsernameToken, or Status. | SAML 2.0 | Yes |
| Key Type | `wst_key_type` | `wst:KeyType`. Bearer, SymmetricKey, or PublicKey. | Bearer | Yes |
| Key Size (symmetric) | `wst_key_size` | Bits. Sent only for SymmetricKey. | 256 | Yes |
| AppliesTo | `wst_applies_to` | `wsp:AppliesTo` / `EndpointReference` / `Address`. | `urn:wstrust:test:rp` | Yes |
| Lifetime (minutes) | `wst_lifetime_minutes` | `wst:Lifetime`. `0` omits it. | 60 | Yes |
| Requested Claims | `wst_claims` | `wst:Claims`. One claim-type URI per line, or comma-separated. | name, emailaddress, givenname, surname, under `.../ws/2005/05/identity/claims/` | Yes |
| OnBehalfOf | `wst_use_onbehalfof` | Include `wst:OnBehalfOf`. | Off | Yes |
| OnBehalfOf token | `wst_onbehalfof` | The token or `SecurityTokenReference` placed inside it. | Empty | Yes |
| ActAs | `wst_use_actas` | Include `wst14:ActAs`. Hidden below version 1.4. | Off | Yes |
| ActAs token | `wst_actas` | The token placed inside it. | Empty | Yes |
| Target Token | `wst_target_token` | Required for Renew, Validate, and Cancel. Becomes `RenewTarget`, `ValidateTarget`, or `CancelTarget`. | Empty | Yes |
| Request status | `wst_config_status` | | | Not stored |

## Credentials / WS-Security

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Add wsu:Timestamp | `wst_add_timestamp` | A timestamp in the security header (WS-Security, section 10). | On | Yes |
| Credential | `wst_cred_mode` | UsernameToken, SAML token, or None. | UsernameToken | Yes |
| Username | `wst_username` | UsernameToken `Username`. | `wstrust` | Yes |
| Password | `wst_password` | Shown in the field. The note under it says it is not persisted. | `wstrust` | Never stored |
| Password Type | `wst_password_type` | PasswordText, or PasswordDigest (`Base64(SHA-1(nonce + created + password))`, UsernameToken Profile). | PasswordText | Yes |
| Import from SAML workflow | | Copies the assertion from the last SAML response into **SAML assertion**. Shown when the credential is a SAML token. | | |
| SAML assertion | `wst_saml_token` | The assertion presented as the WS-Security credential. | Empty | Yes |

On iya-sts in product mode the password in that UsernameToken is an
application password scoped to the WS-Trust door. The account password
is refused there, because the door cannot ask for the second factor
the realm requires. See [setup-iya-sts.md](setup-iya-sts.md).

## Message protection

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Digitally sign the request | `wst_sign_request` | A WS-Security signature over the SOAP body. | Off | Yes |
| Also sign the Timestamp | `wst_sign_timestamp` | Adds the timestamp to the signed references. | On, once signing is open | Yes |
| Signature Algorithm | `wst_sig_alg` | RSA-SHA256, RSA-SHA1, RSA-SHA384, RSA-SHA512. On load, the same draft post-quantum group as the SAML page is appended. | RSA-SHA256 | Yes |
| Key Size | `wst_key_bits` | RSA modulus for **Generate Keys**. | 2048. Also 3072 and 4096. | Yes |
| Generate Keys | | RSA pair and a self-signed certificate. | | |
| Download | | The pair as PEM. | | |
| Private Key | `wst_sp_private_key` | PKCS#8 PEM. | Empty | Key material, behind `wst_save_keypair` (`wstrust_wst_save_keypair`). Clearing the box removes it. |
| Certificate | `wst_sp_cert` | Carried in the signature `KeyInfo`. | Empty | Same checkbox |
| Save this key pair in browser localStorage | `wst_save_keypair` | The response page uses the private key to decrypt an encrypted token. The STS certificate in **Encryption Certificate** is left in storage either way. | On | The preference itself is stored |
| Encrypt the request body | `wst_encrypt_request` | XML Encryption of the body, in the browser, after the signature. Most services will not process an encrypted body. | Off | Yes |
| Encryption Certificate | `wst_enc_cert` | STS certificate that wraps the session key. | Empty | Yes. Not covered by the save-keypair checkbox. |
| Encrypted Type | `wst_enc_type` | Element (the whole RST) or Content. | Element | Yes |
| Canonicalization | `wst_enc_c14n` | | None (serialize as-is). Also exclusive and inclusive C14N 1.0. | Yes |
| Data Encryption Algorithm | `wst_enc_data_alg` | AES-GCM and AES-CBC at 256, 192 and 128, and Triple DES CBC. | AES-256-GCM | Yes |
| Key Transport Algorithm | `wst_enc_key_alg` | RSA-OAEP (XML Encryption 1.1), RSA-OAEP-MGF1P, RSA-1_5. | RSA-OAEP (xmlenc11) | Yes |
| Key Transport Digest | `wst_enc_digest` | | SHA-256 | Yes |
| MGF | `wst_enc_mgf` | | MGF1 with SHA-256 | Yes |

## WS-Addressing

**Add WS-Addressing headers** (`wst_wsa_support`) is on.

| Field | id | When it is blank | Stored |
|---|---|---|---|
| wsa:Action | `wst_wsa_action` | Derived from the operation (Issue, Renew, Validate, Cancel). Edit it to override. | Yes |
| wsa:To | `wst_wsa_to` | The STS URL. | Yes |
| wsa:MessageID | `wst_wsa_messageid` | A `urn:uuid:` value. | Yes |
| wsa:ReplyTo | `wst_wsa_replyto` | The anonymous URI `http://www.w3.org/2005/08/addressing/anonymous`. | Yes |
| wsa:From | `wst_wsa_from` | Omitted. | Yes |

## Send

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Frontend (browser) | `wst_initiateFromFrontEnd` | `fetch` from the page. Needs CORS. | Off | Not stored |
| Backend (proxy) | `wst_initiateFromBackEnd` | `POST /wstrust` on the api. Disabled on a static site, and the frontend radio is forced on. | On | Not stored |
| Validate STS TLS certificate | `wst_ssl_validate` | Checked only for the backend proxy. Clear it for a certificate this api does not trust. | On | Yes |
| Generated Request | `wst_generated_request` | The SOAP document, rebuilt as you edit. **Rebuild** forces that. | | Not stored |
| Send Request | | Posts it and opens `wstrust_response.html`. | | |
| Call status | `wst_call_status` | | | Not stored |

## The response page (`wstrust_response.html`)

| Field | id | What it is | Stored |
|---|---|---|---|
| Status | `wst_resp_status` | `response loaded`, a fault, or a parse error. | Not stored |
| SOAP request | `wst_request_xml` | The request that was sent. | The hand-off is `wstrust_last_exchange` |
| SOAP response | `wst_response_xml` | The full response, including a fault. | Same hand-off |
| Fields | `wst_fields_table` | Operation, action, token type, key type, lifetime, AppliesTo, and the Validate or Cancel status. | Not stored |
| Issued token | `wst_token_xml` | Contents of `RequestedSecurityToken`, or the decrypted assertion after **Decrypt**. | Not stored |
| Token details | `wst_token_details` | | Not stored |
| Validate Signature | | An enveloped signature, with the certificate in `KeyInfo`. | |
| Signature status | `wst_sig_status` | | Not stored |
| Signature details | `wst_sig_details` | | Not stored |
| Decryption Key | `wst_dec_key` | Requestor private key. Prefilled from the signing key when that key was saved. | Not stored |
| Decrypt | | Replaces `EncryptedData` with the token. | |
| Decrypt status | `wst_dec_status` | | Not stored |

## Operations history

Every call is listed, newest first: time, version, operation, username,
and a result of Failure, Sent, or Success. **Clear History** drops the
log. The log is `wstrust_operation_history` in `localStorage`. It holds
no password and no private key.
