---
title: "Pointing the WS-Trust workflow at iya-sts"
---

# Pointing the WS-Trust workflow at iya-sts

Only for [iya-sts](https://rcbj.github.io/iya-sts/). Another security
token service has its own accounts and its own rules for who a token
may be issued to.

**STS URL** is empty in the HTML. When it is still empty the page
writes `https://localhost:8081/sts`. The field's tooltip still shows
an `http://` example. The value the page fills in is `https`.

* TOC
{:toc}

## The account

The username and password fields contain `wstrust` / `wstrust`. That
pair is what the development-mode service accepts, along with any
other password except the literal `invalid`.

Product mode checks the password stored for the account. Create the
person, or use one that already exists, and type that password. The
password is not written to `localStorage`. The screenshots use
`guide-wstrust`.

Product mode also requires a second factor of everybody. The WS-Trust
door cannot ask for one, so the account password is refused there
(`STS-AUTHN-0213`) even when the password itself is right. The
UsernameToken carries an **application password** scoped to the
WS-Trust door, made for that person on iya-sts
(`POST /admin-api/users/create-app-password`, or the person's app
passwords page). It is shown once, it is not the account password, and
it does not work on the browser sign-in screen. The field on this page
stays masked. The signed-request tutorial does not send a
UsernameToken.

## AppliesTo

On Issue and Renew, product mode refuses an `AppliesTo` that is not a
registered application (`STS-WSTRUST-0030`) and a request that omits
one (`STS-WSTRUST-0031`). Validate and Cancel are not asked.

Register an application whose identifier is the audience you will type,
allowed to use WS-Trust, with `wstrustAppliesTo` set to that same
audience. `samlEntityId` is also consulted. The tutorials use three:

| AppliesTo | What the tutorial asks for |
|---|---|
| `urn:wstrust:test:rp` | the bearer Issue, and the signed Issue |
| `https://esb.example.com` | the OnBehalfOf Issue |
| `https://soap1.example.com` | the ActAs Issue |

The service's own audiences, its OAuth issuer and the STS URL itself,
are accepted without an application.

## A signed request

**Digitally sign the request** with **Credential** set to **None**
authenticates by the signature. Product mode accepts that signature
only when the certificate is a message-signing certificate it already
holds for exactly one person or one application, with `digitalSignature`
key usage, or a leaf its own message-signing CA issued.

A key from **Generate Keys** is not one of those until you register
it. The signed tutorial does not use that button in product mode. It
uses a certificate iya-sts issued for `guide-wstrust` (the admin
console's issue-signing-certificate action, or
`POST /admin-api/users/issue-signing-certificate`) and pastes the
PKCS#8 key and the certificate into the signing fields.

A UsernameToken sent beside a signature has to name that same entry.
The signed tutorial sends no UsernameToken.

## An encrypted token

WS-Trust's `wst:EncryptionAlgorithm` and `wst:EncryptWith` name the
cipher and the key transport when response encryption is already on.
They do not choose the element. The page does not send them.

On the relying party, set `wstrustEncryptResponse` to `true` and add
this as one value of `wstrustEncryptResponseElements`:

```
//*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']
```

iya-sts then replaces that assertion with `xenc:EncryptedData`. The
request has to be signed. The recipient is the signature's
`BinarySecurityToken`, unless `wstrustEncryptionCertificate` or
`wstrustResponseRecipientXPath` is set. In product mode a certificate
with only `digitalSignature` is refused once it has been found, and
the token is not sent in the clear. **Generate Keys** writes no
`keyUsage`, so that certificate may be the recipient. A
message-signing certificate from iya-sts may not. Set
`wstrustEncryptionCertificate` to a certificate that permits
`keyEncipherment` or `keyAgreement`, and decrypt with that key.

The response page's **Decrypt** uses the private key of the recipient,
which is the signing key when **Save this key pair** was left on and
that key is the one the service encrypted to.

Leave the STS URL as `https://localhost:8081/sts`. Turn
`wstrustEncryptResponse` back to `false` before the next Issue, or
that call is encrypted too.

## An encrypted request

**Encrypt the request body** replaces the RST with `xenc:EncryptedData`
addressed to **Encryption Certificate**. On iya-sts paste the
application's WS-Trust decryption certificate. Issue one with
`POST /admin-api/applications/issue-wstrust-decryption-key`
(`keyAlg` `rsa-3072`). The certificate comes back as
`wstrustDecryption.certificatePem`, and the private key does not.
Read it again from
`GET /admin-api/applications?application=<id>`, under
`credentials.wstrustDecryption.certificatePem`. An application with
no key of its own takes the realm certificate instead: the first
`KeyDescriptor use="encryption"` in `GET /saml2/metadata`.
`GET /sts/cert` is the signing certificate. Do not encrypt to it.

A request encrypted to a different application's key is refused
(`STS-WSTRUST-0082`). A request for an application that has its own
key, encrypted to the realm key, is refused (`STS-WSTRUST-0083`).
Both faults are `wsse:FailedCheck`. Remove the key with
`POST /admin-api/applications/remove-wstrust-decryption-key` when
later requests should use the realm certificate again.

To require the RST to arrive encrypted, set `wstrustEncryptRequest` to
`true` and add this as one value of `wstrustEncryptRequestElements`:

```
//*[local-name()='RequestSecurityToken']
```

Leave `wstrustAcceptEncryptedElements` unset, or set it to `false`.
That switch overrides `wstrust.acceptEncryptedElements`. Off, which is
the default, ciphertext is accepted only where the request map names
it. Ciphertext the map does not name is `STS-WSTRUST-0080`. Set the
switch to `true` only when a request may encrypt an element no map
names.

That requirement is the application's map. It is not an element of the
RST.

## TLS

**Validate STS TLS certificate (backend)** is on. Leave it on when the
api trusts the service's certificate. The compose stack issues the
api, the client, and iya-sts from one root, so the box stays checked.
A service whose certificate this api does not trust fails the call
until you trust that certificate or clear the box. The checkbox
applies only to the backend proxy. A browser call uses the browser's
trust store.

## Delegation

OnBehalfOf and ActAs are decided by iya-sts's issuance policy. The
page only builds the request.

When the UsernameToken's name and the subject of the token you present
are the same person, the act is for that person. A person acting for
somebody else needs the role `delegation.actorRole` names
(`DELEGATION_ACTOR`, unless the realm changed it). Impersonation, which
is what OnBehalfOf asks for, is allowed only when that person's entry
lists it. An empty list allows delegation only, so ActAs can succeed
while OnBehalfOf is refused.

The target application has to accept the requester
(`appAllowedToActOnBehalfOf`). ActAs also needs the audience of the
presented token to be allowed to delegate to the new audience
(`appAllowedToDelegateTo` on that audience, or the same accept list on
the target).

The tutorials' pictures were taken after that configuration was made
for `guide-wstrust` and the three audiences above. None of it is a
control on the debugger page.
