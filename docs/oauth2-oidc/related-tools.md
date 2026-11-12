---
title: "Token detail, introspection, UserInfo, and JWKS"
---

# Token detail, introspection, UserInfo, and JWKS

Step 2 of the [OAuth2 / OIDC workflow](index.md) links to four small pages.
Each one also stands on its own. **Logout** is a fifth page, and it only
confirms that the browser came back.

Front or back, on the pages that offer it, is the same choice as
[Front end or back end](index.md#front-end-or-back-end). **Front** is the
browser. **Back** is the API. A deployed static site has no API, so **Back**
fails there.

These pages have no screenshots. The pictures in the
[workflow guide](index.md) come from the Selenium jobs, and those jobs were
not re-run for this pass.

* TOC
{:toc}

## Token detail

`/token_detail.html` opens when you click a token's name on step 2. The
page decodes a JWT. An opaque token stays empty, and the page says so. Two
tabs, **JSON** and **Key Pairs**, show the same header and payload: raw
JSON, or one row per member. The table view adds the IANA claim
description where the registry has one.

**Strip newlines from clipboard value** sits beside each **Copy** button
and defaults to off.

Both tabs have the same verification block.

| Field or button | Default | What it does |
|---|---|---|
| **Verification Type** | HMAC Secret | Also X.509 Certificate (PEM), JWKS (JSON), and JWKS (URL). The choice is stored. |
| **JWT Verification Key/URL** | empty | Secret, PEM (a certificate or a bare public key), JWKS JSON, or a URL. JWKS selection is by `kid`, for every algorithm the verifier supports, not only RSA. |
| **Verify Signature** | | Writes **Verification Output**. |

### Claims validation

| Field | Default | What it does |
|---|---|---|
| **JWT Purpose** | Generic JWT (RFC 7519) | Also **OIDC ID Token** and **OAuth2 Access Token (RFC 9068)**. The purpose picks which claim rules run. |
| **Expected Issuer (iss)** | empty | Blank skips the issuer check. |
| **Expected Audience (aud)** | empty | Blank skips the audience check. One value, which must appear in `aud`. |
| **Client ID** | empty | Checked as `azp` for an ID token and as `client_id` for an RFC 9068 access token. |
| **Required Scope(s)** | empty | Space-separated. Every one must be in `scope`. Blank skips the check. |
| **Clock Skew Tolerance (seconds)** | 30 | Applied to `exp`, `nbf`, and `iat`. |
| **Validate Claims** | | Writes the claim-check output under the button. |

**Return to debugger** goes back to step 2.

## Introspection

`/introspection.html` is RFC 7662. Step 2's **Introspect Token** link opens
it with the token filled in.

| Field or button | Default | What it does |
|---|---|---|
| **Hide** / **Show** | the pane is open | `Hide` collapses Configuration Parameters. |
| **OIDC Introspection Endpoint** | empty, stored | From discovery when you came from the workflow. |
| **Initiate the call** | Front | The **Front** radio is first and checked. **Back** is the API. |
| **OIDC Introspection Token** | the token you clicked, stored | Any token. |
| **Token Type Hint** | empty | Also `access_token` and `refresh_token`. |
| **OAuth2 Authentication Type** | Basic Auth | Or Bearer Token. |
| **OAuth2 Client ID** | empty, stored | With **Client Secret**, for Basic Auth. |
| **OAuth2 Client Secret** | empty, stored | The field is a text input and it is stored with the rest of the form. |
| **OAuth2 Bearer Token** | empty, stored | Used when the authentication type is Bearer Token. |
| **Introspect Token** | | The response is **Introspection Endpoint Results**. |

## UserInfo

`/userinfo.html`. Step 2's **Get UserInfo Data** opens it with the access
token filled in.

| Field or button | Default | Stored | What it does |
|---|---|---|---|
| **OIDC UserInfo Endpoint** | empty | yes | From discovery when you came from the workflow. |
| **OIDC UserInfo Method** | GET | yes | Or POST. |
| **Initiate the call** | Front | | **Back** is the API. |
| **OIDC UserInfo Scope** | empty | yes | |
| **OIDC UserInfo Claims** | empty | no | A claims request, when the provider wants one. |
| **OAuth2 Access Token** | the workflow's token | yes | |
| **OP Signing Keys** | JWKS URL (fetched) | yes | Or **JWK Set (pasted below)**. The URL box is prefilled from the workflow's JWKS endpoint. An `HS*` response ignores this and uses the client secret. |
| **Client Secret (HS* only)** | empty | no | The label says it is not saved. |
| **Decryption Key** | empty | no | Private JWK or PKCS#8 PEM, for an encrypted UserInfo response. Not saved. |
| **Expected Issuer** | the workflow's issuer | yes | Blank reports `iss` and does not check it. |
| **Expected Audience** | the workflow's client id | yes | Blank reports `aud` and does not check it. |
| **Retrieve UserInfo** | | | |

Results:

| Field | What it shows |
|---|---|
| **Userinfo Output** | The claims, after a signature check and after decryption. |
| **Response Protection** | Content type, JWE and JWS headers, whether the signature verified, and the `iss`, `aud`, and `sub` checks. Decryption and verification are reported as separate steps. |
| **Raw Response** | The bytes as they arrived. Copy from here when you need the octets a signature covers. |

## JWKS

`/jwks.html`.

| Field or button | What it does |
|---|---|
| **JWKS Endpoint URL** | Stored. From the workflow when you followed a link. |
| **Retrieve** | Fetches the set and draws one row per key, so you can see a rollover. |
| **Clear** | Empties the form and the table. |

## Logout

`/logout.html` is the page the browser returns to after RP-initiated
logout. It shows **Logout successful** and **Return to debugger**. There is
no form. The logout request itself is the **RP-initiated Logout** pane on
step 2 of the workflow. If discovery published an end-session endpoint, that
pane is filled from it. Otherwise paste the URL.
