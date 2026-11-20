---
title: "SAML in the debugger"
---

# SAML in the debugger

The workflow speaks the Web Browser SSO profile. The debugger is the
service provider. The identity provider is whoever's metadata you load.
This page is what those messages are. The fields are in
[reference.md](reference.md), and a click-by-click walk is in
[tutorials.md](tutorials.md).

* TOC
{:toc}

## What you send

On SAML 2.0 the page builds an `AuthnRequest` (SAML Core, section 3.4).
The Issuer is **SP entityID**. The assertion consumer is **ACS URL**,
and `ProtocolBinding` is the **response binding**, which is independent
of the binding that carries the request.

**HTTP-Redirect** puts the deflated, base64-encoded request on a GET to
the identity provider's redirect SingleSignOnService. When signing is
on, `SigAlg` and `Signature` are query parameters. The signature covers
the query string, not an enveloped XML signature (Bindings, section
3.4).

**HTTP-POST** puts an enveloped-signed request, when signing is on, in
a form that the browser submits to the POST SingleSignOnService
(Bindings, section 3.5).

There is no artifact choice for the request. **HTTP-Artifact** is a
response binding. The request still travels by Redirect or POST, and
`ProtocolBinding` asks the identity provider to return an artifact. The
api then calls the Artifact Resolution Service with a SOAP
`ArtifactResolve` and shows the `Response` the service returns. That
back channel is why artifact needs the api, including on the static
sites.

**Call IdP** refuses to send when signing is on and the private key is
empty. Signing is on by default (RSA-SHA256, a 2048-bit key).

## What comes back

The identity provider posts the `SAMLResponse` to the assertion consumer,
or returns an artifact that the api resolves. The api keeps the XML
briefly and redirects the browser to `saml_response.html`.

The response page shows the response, the assertion, and the attributes.
**Validate Signatures** checks each enveloped signature on its own: the
one on the `Response` and the one on the assertion. **Verify with**
defaults to the identity provider's signing certificates from the
metadata. **KeyInfo** checks that the bytes were not altered, and does
not say the signer is the identity provider you loaded.

A `StatusCode` other than Success is still shown. The history row for
that send becomes Success or Failure from the status.

## Single Logout

After a successful 2.0 sign-in the page keeps the NameID and the session
index. **Logout** builds a signed `LogoutRequest` and sends it to the
single logout URL from the metadata, over the request binding. The
`LogoutResponse` comes back through the same consumer the sign-in used
and opens on the response page.

SAML 1.1 has no Single Logout. The button is unavailable there.

## SAML 1.1

SAML 1.1 has no `AuthnRequest`. The browser is sent to the identity
provider's inter-site transfer service with the assertion consumer in
the query. The status code is a QName. Five SAML 2.0 settings are
switched off: the username hint, request signing as a 2.0 signature,
request encryption, Single Logout, and the request-binding selector.
The service-provider key is still used to sign the artifact SOAP when
the response binding is artifact.

Loading metadata whose `protocolSupportEnumeration` names only the
SAML 1.1 protocol moves **Protocol Version** to 1.1. A document that
names both versions does not, and you set the selector. iya-sts
publishes one document for both. See [SAML 1.1](../saml11.md).

## Encrypted assertions

The response page decrypts a `saml:EncryptedAssertion` with **Decryption
Key**, prefilled from the service-provider private key when that key
was saved. Encrypting the `AuthnRequest` itself is off by default. The
form says most identity providers do not accept one.

iya-sts does not encrypt a Web Browser SSO assertion. A provider that
does, such as the stack's Keycloak, returns ciphertext the response
page can open with the same key that signed the request.

## What the identity provider has to know

The request names an Issuer and an assertion consumer, and it is signed
with the key in **Public Signer Certificate**. An identity provider that
checks those will refuse a request it has not been told about. What
iya-sts checks in product mode is in
[setup-iya-sts.md](setup-iya-sts.md). **Download SP Metadata** writes
the `EntityDescriptor` to hand to that registration.
