---
title: "Dynamic client registration"
---

# Dynamic client registration

The **OIDC Dynamic Client Registration** card opens
`oauth2_oidc_1.html#dcr_fieldset`. The same pane is on step 1 of the
[OAuth2 / OIDC workflow](index.md), under the legend **OIDC Dynamic Client
Registration**. The fieldset starts collapsed. Click the legend to open it.

The pane speaks OpenID Connect Dynamic Client Registration 1.0, which is
[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) for the create call and
[RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) for read, update, and
delete.

This page has no screenshot. The pictures in the
[workflow guide](index.md) come from the Selenium jobs, and those jobs were
not re-run for this pass.

## Before you register

Load the provider's metadata first, the way the
[workflow guide](index.md#step-1-load-the-providers-metadata) describes, and
click **Populate Meta Data**. That copies `registration_endpoint` into both
**Registration Endpoint** fields: the one in Configuration Parameters and
the one in this pane. They stay in sync. You can also type the URL.

Set **Redirect URL** on the authorization pane to the URI you want the
client metadata to advertise. The metadata JSON is filled from discovery
and from that redirect URI. Edit the JSON before you register if the
provider requires more members (`grant_types`, `token_endpoint_auth_method`,
and so on).

[iya-sts](https://rcbj.github.io/iya-sts/) is at
`https://localhost:8081`. Its registration endpoint is whatever
`registration_endpoint` says in
`https://localhost:8081/.well-known/openid-configuration`.

## Create

| Field or button | Default | Stored | What it does |
|---|---|---|---|
| **Registration Endpoint** | empty until discovery | yes | POST target for **Register New Client**. |
| **Initial Access Token** | empty | no | Optional bearer token. Leave it empty for open registration. A provider that requires an initial access token rejects a blank one. This value is not written to `localStorage`. |
| **Client Metadata (JSON)** | filled from discovery and the redirect URL | no | The body of the create (POST) and of the update (PUT). |
| **Request** | rebuilt as you edit | no | The POST **Register New Client** will send. Read-only. |
| **Register New Client** | | | Sends that POST. |

## Read, update, delete

A successful create fills the two fields below from the response.

| Field or button | Stored | What it does |
|---|---|---|
| **Registration Client URI** | yes | `registration_client_uri`. You can paste one from an earlier registration. |
| **Registration Access Token** | yes | `registration_access_token`, sent as a bearer token (RFC 7592). |
| **Read Client** | | GET of the client URI. |
| **Update Client** | | PUT of **Client Metadata (JSON)** to the client URI. |
| **Delete Client** | | DELETE of the client URI. |
| **Response** | no | The last response body. Read-only. |

**Read Client**, **Update Client**, and **Delete Client** all present the
registration access token. A create that returned no token cannot be
managed from this pane until you paste one.
