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
delete. **Apply RP metadata choices** on the same pane speaks
[OpenID Connect RP Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html).

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
client metadata to advertise. **Populate Meta Data** fills the metadata
JSON from that redirect URI and from the scopes discovery advertises. It
does not add the [choice arrays](#rp-metadata-choices): a provider that
does not implement RP Metadata Choices may refuse a member it does not
know, and Keycloak does (HTTP 400, `Unrecognized field
"subject_types_supported"`). Edit the JSON before you register if the
provider requires more members (`grant_types`, and so on).

[iya-sts](https://rcbj.github.io/iya-sts/) is at
`https://localhost:8081`. Its registration endpoint is whatever
`registration_endpoint` says in
`https://localhost:8081/.well-known/openid-configuration`.

## Create

| Field or button | Default | Stored | What it does |
|---|---|---|---|
| **Registration Endpoint** | empty until discovery | yes | POST target for **Register New Client**. |
| **Initial Access Token** | empty | no | Optional bearer token. Leave it empty for open registration. A provider that requires an initial access token rejects a blank one. This value is not written to `localStorage`. |
| **Client Metadata (JSON)** | filled by **Populate Meta Data** | no | The body of the create (POST) and of the update (PUT). |
| **Apply RP metadata choices** | | | Rewrites the six choice pairs in the metadata. See [RP metadata choices](#rp-metadata-choices). |
| **Request** | rebuilt as you edit | no | The POST **Register New Client** will send. Read-only. |
| **Register New Client** | | | Sends that POST. |

## RP metadata choices

[OpenID Connect RP Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)
adds one array beside each single-valued registration member. The array
is the set of values this client can use. The single-valued member is
the one it prefers. Section 4 of that specification is the shape of
every pair the button writes:

```json
"id_token_signing_alg_values_supported": ["ES256", "PS256", "RS256"],
"id_token_signed_response_alg": "RS256"
```

The array is this client's set. It is not cut down to the algorithms in
the provider's discovery document. Those stay on the Configuration
Parameters pane, under the same names, and applying choices does not
change them.

**Populate Meta Data** writes only the single-valued partners.
**Apply RP metadata choices** writes the pairs over the metadata in the
box, and leaves
every other member (`client_name`, `scope`, `redirect_uris`, and the
rest) as it was. The line under the box runs the same checks as you
edit. A clean request has an empty finding list. You can still send a
request the line has marked.

The pairs this client sends:

| Array | Partner | Preferred |
|---|---|---|
| `subject_types_supported` | `subject_type` | `public` |
| `id_token_signing_alg_values_supported` | `id_token_signed_response_alg` | `RS256` |
| `userinfo_signing_alg_values_supported` | `userinfo_signed_response_alg` | `RS256` |
| `userinfo_encryption_alg_values_supported` | `userinfo_encrypted_response_alg` | `RSA-OAEP-256` |
| `userinfo_encryption_enc_values_supported` | `userinfo_encrypted_response_enc` | `A128CBC-HS256` |
| `token_endpoint_auth_methods_supported` | `token_endpoint_auth_method` | `client_secret_basic` |

`subject_types_supported` is `public` and `pairwise`. Core 1.0
section 8.1 needs a `sector_identifier_uri` once the redirect URIs span
more than one host, and the provider fetches that document. This
client publishes none, so with redirect URIs on two hosts and no
`sector_identifier_uri` typed, `pairwise` is dropped from the array
instead. A value you already typed is left as it is, and `pairwise`
stays offered with it.

The ID Token signing list is the JWS algorithms this client verifies,
without `none`. The UserInfo signing list is that same list plus
`none`, because a UserInfo response may be plain JSON. The UserInfo
encryption lists are the `alg` and `enc` values this client decrypts.
`token_endpoint_auth_methods_supported` is `client_secret_basic`, which
is how the token request authenticates, and section 3 uses that one
list for the token, revocation, introspection and pushed-authorization
endpoints.

The generated request omits these members. This client has no supported
value for any of them. A request you edit by hand is still checked, and
a value in one of them is reported as outside the set this client can
use:

- `id_token_encryption_alg_values_supported`
- `id_token_encryption_enc_values_supported`
- `request_object_signing_alg_values_supported`
- `request_object_encryption_alg_values_supported`
- `request_object_encryption_enc_values_supported`
- `token_endpoint_auth_signing_alg_values_supported`
- `backchannel_authentication_request_signing_alg_values_supported`
- `authorization_signing_alg_values_supported`
- `authorization_encryption_alg_values_supported`
- `authorization_encryption_enc_values_supported`
- `introspection_signing_alg_values_supported`
- `introspection_encryption_alg_values_supported`
- `introspection_encryption_enc_values_supported`

`revocation_endpoint_auth_methods_supported` and
`introspection_endpoint_auth_methods_supported` are not client
metadata. The verdict names section 3, and Apply removes them.

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

After **Register New Client**, **Read Client**, or **Update Client**,
the table under the response shows each choice member, the values that
were offered, the preferred value, the returned value, and the value
kept. The metadata box becomes that kept request, so the next update
sends section 4 input again. A returned partner that sits in the
offered array is kept, including one that differs from the preference.
A returned partner outside that array is not kept. Choice arrays in
the response are not kept: a response carries the selected partner.
The response box still shows the raw body.

**Read Client**, **Update Client**, and **Delete Client** all present the
registration access token. A create that returned no token cannot be
managed from this pane until you paste one.
