# Optional: setting up iya-sts for the VC tutorials

> **This page applies ONLY to iya-sts.** The debugger works with **any**
> OpenID4VCI Credential Issuer and any OpenID4VP Verifier; walt.id, Keycloak's
> OID4VCI support and the rest are examples, not a closed list. Nothing here
> is a step of the tutorials: they ask you to obtain an account, a client and
> an offer **from your issuer**, however your issuer does that. Use this page
> only if your issuer happens to be iya-sts.

[iya-sts](https://rcbj.github.io/iya-sts/) is the security token service the
debugger's test suite runs against. Its OpenID4VCI issuer is at the service's
origin (`https://localhost:8081` on the local stack). The instructions below
were written against iya-sts **1.1.0** (the management API reports version
`1.1.0.20261117002318` on that stack) and its published OpenAPI document,
`GET /admin-api/openapi.json`; another release may differ, and that document
is the authority.

- [What the tutorials need from an issuer](#what-the-tutorials-need-from-an-issuer)
- [Development mode and product mode](#development-mode-and-product-mode)
- [A token for the management API](#a-token-for-the-management-api)
- [A holder account](#a-holder-account)
- [A wallet client](#a-wallet-client)
- [A confidential client, private_key_jwt and a Client Attestation](#a-confidential-client-private_key_jwt-and-a-client-attestation)
- [Offers](#offers)
- [Removing it all again](#removing-it-all-again)

## What the tutorials need from an issuer

> **iya-sts only.** Any other issuer has its own way to provide these.

| Tutorial | Needs |
|---|---|
| [Read a Credential Issuer's metadata](tutorial-issuer-discovery.md) | nothing |
| [Receiving a credential](tutorials-issuance.md), pre-authorized offers | a **holder account** that can sign in to the issuer's offer page |
| [Receiving a credential](tutorials-issuance.md), authorization code and refresh | a holder account and a **public wallet client** with the debugger's `/callback` as a redirect URI |
| [Receiving a credential](tutorials-issuance.md), client authentication | a **confidential client** with a secret, a JWKS, and a trusted Client Attestation issuer |
| [Presenting](tutorial-present-to-verifier.md), [DIDs](tutorial-did-linkage.md), [tools](tutorials-tools.md) | nothing from the issuer |

## Development mode and product mode

> **iya-sts only.**

In **development mode** iya-sts creates an account the first time somebody
signs in and serves a client it has only seen; the suite's stacks run that
way, and nothing below is needed. In **product mode** (`STS_MODE=product`)
it serves only clients registered ahead of time — its error says so:
*"In product mode this authorization server serves only a client registered
ahead of time (the console, /admin-api, RFC 7591, an LDAP add under
ou=applications or an OpenID Federation)"* — and signs in only people who
exist. Everything below is for product mode. Do not switch a shared service's
mode to avoid it.

Everything below can also be done in the **admin console** at `/admin`,
whose pages are the same operations over forms. The management API is shown
because a call can be quoted exactly.

## A token for the management API

> **iya-sts only.**

`/admin-api` takes an OAuth 2.0 access token audienced to itself, carrying
`admin:read` to read and `admin:write` to write, issued to the seeded
`sts-api-client` client by `client_credentials`:

```bash
curl -s https://localhost:8081/oauth2/token \
  -u 'sts-api-client:<your sts-api-client secret>' \
  -d grant_type=client_credentials \
  -d 'scope=admin:read admin:write' \
  -d resource=https://localhost:8081/admin-api
```

**The secret is per installation.** It is minted at each start unless the
operator pins it (`ADMIN_API_CLIENT_SECRET` on the container); ask whoever
runs the service. Never put it in a file, a page or a screenshot. The
debugger's test tooling mints the same token with
`tests/tools/admin-api-token.js` from the environment variable
`STS_ADMIN_API_CLIENT_SECRET`.

Every call below is `POST https://localhost:8081/admin-api/<path>` with
`Authorization: Bearer <token>` and a JSON body.

## A holder account

> **iya-sts only.**

`users/create` puts a person in the directory before they sign in. With
`credential: "password"` the password you send is set (hashed, never shown
again); the default, `generate`, draws one and returns it once.

```json
POST /admin-api/users/create
{
  "username": "vc-guide-holder",
  "invent": false,
  "credential": "password",
  "password": "<a password that meets the realm's policy>",
  "attributes": { "cn": "VC Guide Holder", "givenName": "VC",
                  "sn": "Guide Holder", "mail": "vc-guide-holder@example.test" }
}
```

`GET /admin-api/users/new` lists the attribute names the directory accepts;
the claims the issuer puts in a credential come from these attributes.
`users/set-password` (`{ "user", "password" }`) changes the password of an
existing account.

## A wallet client

> **iya-sts only.**

A public OAuth client the debugger's issuance pages use as their `client_id`,
with the debugger's `/callback` as its redirect URI (here
`https://localhost:3000/callback`; on another deployment, that deployment's
origin):

```json
POST /admin-api/applications/create
{
  "identifier": "vc-user-guide-wallet",
  "name": "VC user guide wallet",
  "protocols": ["oauth2", "oid4vci"],
  "fields": {
    "oauthClientId": "vc-user-guide-wallet",
    "oauthGrantType": ["urn:ietf:params:oauth:grant-type:pre-authorized_code",
                       "authorization_code", "refresh_token"],
    "oauthRedirectUri": ["https://localhost:3000/callback"],
    "oauthResponseType": ["code"],
    "oauthTokenEndpointAuthMethod": "none",
    "oauthAllowedScope": ["openid", "profile", "email", "offline_access",
                          "identity_credential", "identity_credential_jwt",
                          "identity_credential_ldp", "identity_credential_did",
                          "identity_credential_ldp_did"]
  }
}
```

`oauthAllowedScope` is what the client may ask for: list every credential
`scope` in the issuer's `credential_configurations_supported` (the ones above
are the 8081 issuer's) besides the OpenID scopes. `GET
/admin-api/applications/new` publishes the protocol ids and attribute names.
Then set `client_id` on issuance step 1 to `vc-user-guide-wallet`.

## A confidential client, private_key_jwt and a Client Attestation

> **iya-sts only.**

A second application, declaring the credentialed methods:

```json
POST /admin-api/applications/create
{
  "identifier": "vc-user-guide-confidential",
  "protocols": ["oauth2", "oid4vci"],
  "fields": {
    "oauthClientId": "vc-user-guide-confidential",
    "oauthGrantType": ["urn:ietf:params:oauth:grant-type:pre-authorized_code",
                       "refresh_token"],
    "oauthTokenEndpointAuthMethod": ["client_secret_basic",
      "client_secret_post", "private_key_jwt", "attest_jwt_client_auth"]
  }
}
```

then its credentials, one attribute at a time with `applications/set`
(`{ "application", "attribute", "value" }`):

- `oauthClientSecret` — the secret you will type on steps 2 and 4;
- `oauthJwks` — the **Public JWKS** step 1's Client Authentication pane shows
  after **Generate**, as a JSON string, for `private_key_jwt`.

For `attest_jwt_client_auth` the authorization server must trust the
attester: put the **Attester JWKS** the pane shows after **Make one** (or
your wallet provider's) in the setting `oauth2.clientAttestationTrustedKeys`
with `config/set` (`{ "key", "value" }`). That is a setting, not an entry,
so it affects every client of the realm it is set in; the debugger's suite
sets it in a trust realm of its own (`realms/create`, then the call under
`/realm/<id>/admin-api/config/set`) rather than on the service's default
realm, and that is the safer choice on a shared service.

## Offers

> **iya-sts only.**

A **pre-authorized** offer is made for a person who is signed in: open
`https://localhost:8081/portal/wallet`, sign in as the holder, choose the
credential configuration and *cross-device* (or *deferred*), and make the
offer. The page shows the `openid-credential-offer://` URI, its QR code and,
separately, the Transaction Code — take them to issuance step 1 as the
tutorial describes.

An offer with the **authorization code** grant authorizes nothing by itself;
iya-sts's development companion (`http://localhost:9700/issuer`, run by the
test stacks and not part of the service) makes one per configuration. Any
wallet-initiated issuance from step 1 works the same without an offer.

## Removing it all again

> **iya-sts only.**

`users/delete` (`{ "user": "vc-guide-holder" }`) removes the account, and
`applications/forget` (`{ "application": "vc-user-guide-wallet" }`) deletes
an application entry entirely (`applications/remove` only removes one value
of an attribute). A setting changed with `config/set` is put back with
`config/reset` (`{ "key" }`), and a realm made for the purpose is removed,
with everything in it, by `realms/remove` (`{ "id" }`).
