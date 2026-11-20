---
title: "Pointing the SAML workflow at iya-sts"
---

# Pointing the SAML workflow at iya-sts

Only for [iya-sts](https://rcbj.github.io/iya-sts/). Another identity
provider has its own registration. The tutorials do not depend on this
page.

On a fresh browser the form is filled with Keycloak-shaped placeholders
under `http://localhost:8080/samlp/...`. **Load Metadata** replaces
them.

* TOC
{:toc}

## The metadata URL

iya-sts publishes SAML 2.0 metadata at:

`https://localhost:8081/saml2/metadata`

That document describes the identity provider. Put it in **Metadata
Document URL** and click **Load Metadata**. The entityID, the SSO and
SLO URLs, the artifact resolution service, the NameID formats, and the
signing certificate all come from it.

A second URL, `https://localhost:8081/saml2/metadata/app-<12 hex>`, is
the descriptor for one relying party. The twelve hex characters are the
start of the SHA-256 of the service-provider entityID. In product mode
that URL is answered only when the relying party is already registered.
The generic document above is the one to load first.

SAML 1.1 metadata for one relying party is the same document:

`https://localhost:8081/saml11/metadata/app-<12 hex>`

It names both protocols, so **Load Metadata** leaves **Protocol
Version** on 2.0. Set it to **SAML 1.1**. A document from another
provider that names only the 1.1 protocol moves the selector by
itself. In product mode that per-relying-party URL is answered only
when the relying party is registered for SAML 1.1.

## Product mode

iya-sts in **product** mode checks the request. Development mode is
looser: any password other than the literal `invalid` is accepted, and
an unregistered Issuer can still be answered. The screenshots in the
tutorials were taken in product mode. What that mode requires:

**An account with a password.** The sign-in screen checks the password
stored for that person. The literal password `invalid` is refused in
every mode. The screenshots sign in as `guide-saml`. The password is
whatever you set for that account. It is not stored by the debugger,
and this page does not print one.

**A second factor.** Product mode requires one of everybody. After the
password, the sign-in page asks you to set up an authenticator app or
a passkey if the account does not have one yet. There is no skip. The
tutorials show the password form and not that set-up page, because the
set-up page displays a shared secret. A later sign-in in the same
browser session asks for the current code from that app. Clearing the
realm's second-factor requirement is not part of this workflow.

**Consent, once per service provider.** After the factors, product mode
asks whether this service provider may sign you in. **Allow** is
remembered on the account, so the question is not repeated for that
provider. **Deny** comes back as a SAML `RequestDenied` response.
Development mode does not ask. A passive request is not shown the
screen.

**A registered service provider**, before **Call IdP**. The application
identifier is the SP entityID (the local default is
`https://localhost:3000/saml/sp`). It needs:

| What the request will claim | Registry attribute |
|---|---|
| Issuer | `samlEntityId` |
| Where the response is posted | `samlAssertionConsumerService`, the page's ACS URL. An artifact response also needs the artifact consumer, the ACS with `/samlacs` replaced by `/samlacs/artifact`. |
| Where logout is posted | `samlSingleLogoutService`, from the SP metadata the page builds |
| The key that signs the AuthnRequest | `samlSigningCertificate`, the public certificate the page generated |

The local ACS default is `https://localhost:4000/samlacs`. Register the
URL the page is actually sending. A different deployment, including the
static sites, uses a different consumer.

A signature that is present is checked against that registered
certificate, not against the certificate inside the request. With no
certificate registered, a signature is recorded and treated as absent.
Product mode requires a signed AuthnRequest, and the page signs by
default, so the certificate has to be the one **Generate Keys** just
wrote. Register it, or upload the file from **Download SP Metadata**,
before **Call IdP**.

**NameID format.** Leave **Supported NameIDFormat** on the value the
identity-provider metadata selected. Asking for a format the service
provider's own metadata does not declare is refused. The page's
downloaded metadata is the declaration.

**SAML 1.1.** The same application has to be allowed to use SAML 1.1,
and the identity provider needs the service provider's 1.1 metadata
(the profiles and the NameID formats). **Download SP Metadata** after
the version selector has moved to 1.1 is that document. Upload it on
the iya-sts admin API as SAML 1.1 metadata for this entityID, or
register the same facts by hand.

## Development mode

Development mode still refuses the password `invalid`. It does not
require the registration above for a sign-in to complete. A signature
is still checked when a certificate is registered. Registering the
service provider in development mode does not change a successful
sign-in. It is what makes the two modes comparable.
