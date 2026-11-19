---
title: "WS-Trust in the debugger"
---

# WS-Trust in the debugger

The page builds one `RequestSecurityToken` and shows the
`RequestSecurityTokenResponse` the service returns. The fields are in
[reference.md](reference.md). A click-by-click walk is in
[tutorials.md](tutorials.md).

* TOC
{:toc}

## The request

**WS-Trust Version** selects the namespace. 1.0 uses
`.../ws/2004/04/trust`. 1.1 and 1.2 use `.../ws/2005/02/trust`. 1.3 and
1.4 use `.../ws-sx/ws-trust/200512`. **Bearer** is offered from 1.3.
**ActAs** is offered on 1.4. Other versions hide those controls.

**Operation** is the `RequestType`: Issue, Renew, Validate, or Cancel.
Renew, Validate, and Cancel need the token they act on in **Target
Token**. It is sent as `RenewTarget`, `ValidateTarget`, or
`CancelTarget`.

**Token Type** asks for a SAML 2.0 assertion, a SAML 1.1 assertion, a
JWT, a UsernameToken, or a status. **Key Type** is Bearer,
SymmetricKey, or PublicKey. The key size is sent only for a symmetric
key. **AppliesTo** is `wsp:AppliesTo`, the address the token is for.
**Lifetime** is minutes. Zero omits `wst:Lifetime`.

**Requested Claims** is one claim-type URI per line. The default four
are name, emailaddress, givenname, and surname, under
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/`.

SOAP 1.2 sends `application/soap+xml` with the action in the content
type. SOAP 1.1 sends `text/xml` and a `SOAPAction` header.

## Who is asking

**UsernameToken** is the default credential. **PasswordText** sends the
password. **PasswordDigest** sends `Base64(SHA-1(nonce + created +
password))`. The password is not stored. On iya-sts in product mode
that value is an application password scoped to WS-Trust. The account
password is refused, because that door cannot ask for a second factor.
See [setup-iya-sts.md](setup-iya-sts.md).

**SAML token** presents an assertion as the WS-Security credential.
**Import from SAML workflow** fills it from the last SAML response.

**None** sends no username and no assertion. A signed request can
still name the caller by the signing certificate. An unsigned request
with no credential is anonymous, and a service is free to refuse it.

## Signing and encryption

**Digitally sign the request** is off by default. When it is on, the
page signs the SOAP body with a WS-Security signature. **Also sign the
Timestamp** adds the timestamp to the signed references. The
certificate is carried in `KeyInfo`.

On iya-sts in product mode that signature is the authentication, and
the certificate has to be one the service knows. A key the page
generates and has never shown the service is refused. See
[setup-iya-sts.md](setup-iya-sts.md).

**Encrypt the request body** is off. The form says most services will
not process an encrypted body. Encryption runs in the browser, after
the signature.

A service can encrypt the token it issues. iya-sts does that when the
STS URL carries `encrypt=1`, and it encrypts to the certificate on the
request's signature. The response page decrypts with **Decryption
Key**, prefilled from the signing key when that key was saved.

## Delegation

**OnBehalfOf** puts a token in `wst:OnBehalfOf`. That is impersonation:
the caller asks for a token about the subject of the token they
present. **ActAs** puts a token in `wst14:ActAs`. That is composite
delegation: the new token says both who asked and who they acted as.

Both are off until you tick them. ActAs is hidden below WS-Trust 1.4.

What the service allows is its policy. On iya-sts a person who acts
for somebody else needs the delegation actor role. A caller who
presents a token about themselves, and authenticates as that same
person, is not acting for anyone else.

## What the response page shows

The SOAP request, the full response, and a **Fields** tab: operation,
action, token type, key type, lifetime, AppliesTo, and the Validate or
Cancel status. **Issued Token** is the contents of
`RequestedSecurityToken`. **Validate Signature** checks an enveloped
signature with the certificate in `KeyInfo`. **Decrypt** replaces an
`EncryptedData` with the assertion.

## WS-Addressing

**Add WS-Addressing headers** is on. `wsa:Action` is derived from the
operation until you edit it. `wsa:To` defaults to the STS URL.
`wsa:MessageID` is a `urn:uuid:` value when blank. `wsa:ReplyTo`
defaults to the anonymous URI. `wsa:From` is omitted when blank.
