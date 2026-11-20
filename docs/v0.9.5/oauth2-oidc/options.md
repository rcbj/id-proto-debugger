# Request options, token details and JWT validation

Options of the OAuth 2.0 / OpenID Connect workflow beyond the grants themselves.

## State Parameters
* A state parameter can be submitted as part of the authorization endpoint request. The state parameter will be validated when the redirect comes back to the registered callback endpoint. A UUID is used as the state value. This is an optional, but recommended parameter.
## Custom Parameters
Various specs & RFCs that build on the OAuth2 & OIDC protocols add additional parameters that must be passed to the Authorization Endpoint and Token Endpoint. The debugger supports passing up to ten custom parameters.
## Nonce Parameter
A nonce parameter can be included in the Authorization Endpoint call. A UUID is used as the nonce value.

## Token Details
All tokens (Access, Refresh, ID) returned by the IdP can have their details viewed by clicking on the link next to the token on the Debugger2 page.

This feature currently only supports JWT tokens, but in the future will support other token types.

There are two views: raw-JSON or table view.

The table view will display a claim description for spec-defined claims.

Some caveats to keep in mind:

* If nothing is displayed, then the requested token retrieved from the endpoint is not a JWT or not a valid JWT.
* In the future, additional token formats may be added.
* Although, many leading IdPs use JWT as the format for OAuth2 access tokens and refresh tokens. The spec does not require this.
* Some IdPs intentionally use opaque tokens that have no deeper meaning than to be a randomly generated identifier that points back to session information stored on the IdP

## OIDC RP-Initiated Logout Spec Support
If the Logout URL can be read from the OIDC Discovery Endpoint, it will be automatically populated; otherwise, you will need to manually copy in this URL.

The associated refresh token should be invalidated at this point. The corresponding JWT tokens could still be validated unless you compare them against the Introspection Endpoint.

## JWT Validation

The token detail page (`/token_detail.html`) checks a JWT signature. Open
it by clicking the token's name on step 2. **Verification Type** defaults
to **HMAC Secret**. The other choices are **X.509 Certificate (PEM)** (a
certificate or a bare public key), **JWKS (JSON)**, and **JWKS (URL)**. A
JWKS is selected by `kid` and verifies every algorithm this page can check,
not only RSA.

Field-by-field notes for that page, and for introspection, UserInfo, JWKS,
and the logout status page, are in
[Token detail, introspection, UserInfo, and JWKS](related-tools.md).
