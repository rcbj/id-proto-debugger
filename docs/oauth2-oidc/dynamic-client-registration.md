---
title: "Dynamic client registration"
---

# Dynamic client registration

The registration pane on `oauth2_oidc_1.html` (`#dcr_fieldset`) creates,
reads, updates and deletes a client. **Apply RP metadata choices** is
part of that pane.

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

**Populate Meta Data** already writes the pairs. **Apply RP metadata
choices** writes them again over the metadata in the box, and leaves
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

`subject_types_supported` is `public` and `pairwise`. With one redirect
URI, `sector_identifier_uri` is not required. A second redirect URI,
while `pairwise` is still offered, adds
`https://client.example.org/sector.json` when that member is missing.
A value you already typed is left as it is.

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

After **Register New Client**, **Read Client** or **Update Client**,
the table under the response shows the member, the values that were
offered, the preferred value, the returned value and the value kept.
The metadata box becomes that kept request, so the next update sends
section 4 input again. A returned partner that sits in the offered
array is kept, including one that differs from the preference. A
returned partner outside that array is not kept. Choice arrays in the
response are not kept: a response carries the selected partner. The
response box still shows the raw body.

This page has no screenshot.
