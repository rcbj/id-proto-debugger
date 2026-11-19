---
title: "Using the SAML workflow"
---

# Using the SAML workflow

The debugger is a SAML service provider. It builds the request, sends it
to an identity provider you choose, and shows the response that comes
back:

* **the request** — `saml_request.html`, from the **SAML Protocol** card;
* **the response** — `saml_response.html`, opened when the assertion
  consumer service has caught what the identity provider posted.

**Protocol Version** defaults to **SAML 2.0**. SAML 1.1 is a different
exchange, walked in the [tutorials](tutorials.md#saml-11) and described
in [SAML 1.1](../saml11.md). **SAML 1.0 (reference only)** fills the form
and does not complete a sign-in.

These pages are for somebody **using** the debugger. Why a check is made
the way it is lives in the developer notes listed
[at the end](#developer-notes).

* TOC
{:toc}

## Before you start

Start the debugger as [Getting started](../getting-started.md)
describes, open `https://localhost:3000`, and choose **SAML Protocol**.
The deployed copies at [idptools.com](https://idptools.com) and
test.idptools.com have the pages too. What they can finish is
under [static sites](#what-the-static-sites-can-and-cannot-do).

**The identity provider is yours to choose.** Nothing on these pages is
specific to one product. The values you need are that provider's metadata,
the entityID and assertion consumer it will accept, and an account it
will sign in. The screenshots here use iya-sts at
`https://localhost:8081`. Another provider has its own registration and
its own sign-in page.

**Where a URL is fetched from.** With a backend, **Load Metadata** is
fetched by the api (`GET /samlmetadata`), and an HTTP-Artifact response
is resolved by the api as well. The URL has to be reachable from the
api process. A name that works in the browser can still fail there when
the api runs in another container and `localhost` means that container.
**Upload Metadata** reads a file in the browser and does not use the api.

## What the static sites can and cannot do

The deployed copies are S3 and CloudFront with no backend. They store
nothing. The assertion consumer and the single logout endpoint on those
sites are Lambda@Edge functions (`/samlacs`, `/samlslo`).

**Works on the static sites:**

- SAML 2.0 sign-in over HTTP-Redirect and HTTP-POST. The identity
  provider's POST is received at the edge and handed to
  `saml_response.html`.
- Loading metadata in the browser, when the identity provider sends CORS
  headers for the debugger's origin. Otherwise use **Upload Metadata**.
- Reading the response, checking signatures, and decrypting an encrypted
  assertion. Decryption uses the service-provider private key, which
  stays in the browser.
- The [decoders](../saml-decoders.md) and the
  [SAML Assertion Tool](../saml-assertion.md). They need no network.

**Not available on the static sites:**

- **HTTP-Artifact.** Resolving the artifact is a SOAP call the browser
  does not make. It needs the api.
- **Single logout** on a site whose edge function is not deployed for
  `/samlslo`. The containerized stack answers it on the api.

## Optional: iya-sts setup

[setup-iya-sts.md](setup-iya-sts.md) is only for iya-sts. It says what
product mode requires before a sign-in succeeds: a registered service
provider, the signing certificate, and an account whose password is
real. Every other identity provider has its own way, and the tutorials
do not depend on that page.

## Configuration reference

Every pane, field and button, with its element id, the specification
that defines it, its default, and whether it is stored.

| Page | Reference |
|---|---|
| `saml_request.html` and `saml_response.html` | [reference.md](reference.md) |

## Protocol

What the workflow sends, which binding carries it, and what the response
page checks.

| | |
|---|---|
| SAML 2.0 Web Browser SSO, the three bindings, and Single Logout | [protocol.md](protocol.md) |
| SAML 1.1, and why it is not an older spelling of 2.0 | [../saml11.md](../saml11.md) |

## Tutorials

Each tutorial is one way the workflow is used. The pictures were taken
against iya-sts. Your identity provider's sign-in page will look
different. The debugger's panes are the same.

| You want to | Tutorial |
|---|---|
| Sign in over HTTP-Redirect and read the assertion | [Sign in over HTTP-Redirect](tutorials.md#sign-in-over-http-redirect) |
| Send the AuthnRequest as a POST | [HTTP-POST](tutorials.md#send-the-authnrequest-as-a-post) |
| Ask for an artifact and let the api resolve it | [HTTP-Artifact](tutorials.md#ask-for-an-artifact) |
| End the session | [Single Logout](tutorials.md#single-logout) |
| Speak SAML 1.1 | [SAML 1.1](tutorials.md#saml-11) |

An encrypted assertion is decrypted on the response page. iya-sts does
not encrypt a Web Browser SSO assertion, so that walk is not pictured
here. The field is in the [reference](reference.md#decrypting-an-assertion).

## Related pages

* [SAML Assertion Tool](../saml-assertion.md) — build an assertion by
  hand. Private keys on that page are stored, and there is no
  save-keypair checkbox.
* [SAML decoders and certificate details](../saml-decoders.md) —
  nothing pasted there is stored.
* [WS-Federation](../wsfed.md) — a different sign-in profile.
* [Post-quantum XML Signature](../xmldsig-pqc.md) — the draft
  SignatureMethod values added to the algorithm menu on load.

## Developer notes

* [SAML 1.1](../saml11.md)
* [Post-quantum XML Signature](../xmldsig-pqc.md)

## Regenerating the screenshots

The pictures are taken by `tests/saml_wstrust_user_guide.js` through
`tests/doc_screenshots.js`. That helper does nothing unless
`DOC_SCREENSHOT_DIR` is set. The job is **not** part of the ordinary
suite, so a normal test run takes none of these pictures. A file is
named `<prefix>-<step>.png`. The Markdown links to those names, so
renaming a `snap()` breaks a picture here.

The walk signs in as the account named by `GUIDE_SAML_USER` (default
`guide-saml`). The password is `GUIDE_SAML_PASSWORD` and is only read
from the environment. Registering the service provider on iya-sts uses
the admin API and needs `STS_ADMIN_API_CLIENT_SECRET`, also only in
the environment. Neither value belongs in a command that is committed.

In product mode the job enrolls an authenticator app for that account
the first time the sign-in asks for one, and it creates an application
password scoped to WS-Trust for `GUIDE_WST_USER`. Neither secret is
written into this repository.

```bash
cd tests
export CONFIG_FILE=$PWD/env/local.js
export DOC_SCREENSHOT_DIR=$PWD/../docs/saml/images
export WSTRUST_SCREENSHOT_DIR=$PWD/../docs/wstrust/images
export GUIDE_SAML_USER=guide-saml
export GUIDE_WST_USER=guide-wstrust
# GUIDE_SAML_PASSWORD, GUIDE_WST_PASSWORD and
# STS_ADMIN_API_CLIENT_SECRET come from the environment.
node saml_wstrust_user_guide.js -u https://localhost:3000 \
  --sts https://localhost:8081
```

`STS_SPKI_PIN` and `STACK_TLS_SPKI_PIN` are the pins Chrome is given
for the two certificates, the same way the rest of the suite trusts
them. `-b` shows the browser.
