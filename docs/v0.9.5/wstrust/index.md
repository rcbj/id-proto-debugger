---
title: "Using the WS-Trust workflow"
---

# Using the WS-Trust workflow

The debugger is a WS-Trust client. `wstrust_tools.html` builds a SOAP
`RequestSecurityToken` and sends it to a security token service you
choose. `wstrust_response.html` shows the answer.

The version selector defaults to **WS-Trust 1.4**. SOAP defaults to
1.2. The four operations are Issue, Renew, Validate, and Cancel.

These pages are for somebody **using** the debugger.

* TOC
{:toc}

## Before you start

Start the debugger as [Getting started](../getting-started.md)
describes, open `https://localhost:3000`, and choose **WS-Trust
Protocol**.

**The security token service is yours to choose.** The screenshots use
iya-sts at `https://localhost:8081/sts`. Another service has its own
accounts and its own policy for `AppliesTo`.

**Backend or browser.** **Initiate STS Call From** defaults to
**Backend (proxy)**, which is `POST /wstrust` on the api. The STS URL
then has to be reachable from the api. **Frontend (browser)** calls
that URL from the page, which needs the service to send CORS headers
for the debugger's origin. iya-sts does.

On a deployed static site the backend choice is disabled. The call is
made from the browser, so the service must allow that origin.

## What the static sites can and cannot do

The static sites have the page. They have no api, so **Backend
(proxy)** is off and **Validate STS TLS certificate** has nothing to
apply to. A service that answers a browser, iya-sts included, can still
be called with **Frontend (browser)**.

## Optional: iya-sts setup

[setup-iya-sts.md](setup-iya-sts.md) is only for iya-sts. Product mode
checks the password, requires a registered `AppliesTo` on Issue and
Renew, and authenticates a signed request by a certificate it issued
or that you registered. The tutorials do not depend on that page when
the service you call is not iya-sts.

## Configuration reference

| Page | Reference |
|---|---|
| `wstrust_tools.html` and `wstrust_response.html` | [reference.md](reference.md) |

## Protocol

| | |
|---|---|
| Issue, Renew, Validate, Cancel, delegation, and a signed request | [protocol.md](protocol.md) |

## Tutorials

| You want to | Tutorial |
|---|---|
| Ask for a bearer SAML assertion | [Issue a bearer token](tutorials.md#issue-a-bearer-token) |
| Renew it, validate it, and cancel it | [Renew, validate, cancel](tutorials.md#renew-validate-and-cancel) |
| Authenticate with a signature | [Sign the request](tutorials.md#sign-the-request) |
| Receive an encrypted token and open it | [An encrypted token](tutorials.md#an-encrypted-issued-token) |
| Act for the subject of a token you already hold | [OnBehalfOf and ActAs](tutorials.md#onbehalfof-and-actas) |

## Related pages

* [SAML workflow](../saml/index.md) — **Import from SAML workflow**
  copies the last assertion into the SAML-token credential.
* [WS-Federation](../wsfed.md) — the passive profile, which carries a
  WS-Trust response in `wresult`.
* [Post-quantum XML Signature](../xmldsig-pqc.md) — the draft methods
  added to the signature menu on load.

## Regenerating the screenshots

The pictures are taken by the same job as the SAML guide,
`tests/saml_wstrust_user_guide.js`. It is not part of the ordinary
suite. WS-Trust pictures go to `WSTRUST_SCREENSHOT_DIR`. The account
is `GUIDE_WST_USER` (default `guide-wstrust`) with
`GUIDE_WST_PASSWORD` from the environment. In product mode the
UsernameToken uses an application password the job creates for the
WS-Trust door, not that account password. The command is on the
[SAML guide](../saml/index.md#regenerating-the-screenshots).
