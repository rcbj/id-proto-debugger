# Client authentication in the VC issuance workflow

How the wallet authenticates to the authorization server's token endpoint,
for **every** token call the workflow makes:

- the authorization-code exchange, made on `oauth2_oidc_2.html` while the
  VC flow drives that page;
- the pre-authorized code grant on step 2 (OID4VCI 1.0 §6.1 leaves it to
  the authorization server whether this grant needs client
  authentication);
- the refresh on step 4 (RFC 6749 §6 requires a confidential client to
  authenticate a refresh).

Before this, the workflow sent `client_id` alone, and step 4 read a
`client_secret` from storage that nothing wrote and nothing may.

## Methods

`client/src/client_auth.js` is the engine, with no DOM:

| Method | Wire form |
|---|---|
| `none` | `client_id` in the body |
| `client_secret_basic` | `Authorization: Basic` over the **form-urlencoded** `client_id` and secret (RFC 6749 §2.3.1 and Appendix B; Basic over the raw strings breaks on the first secret with a colon in it) |
| `client_secret_post` | `client_id` and `client_secret` in the body |
| `client_secret_jwt` | An HMAC client assertion keyed by the secret (RFC 7523 §2.2) |
| `private_key_jwt` | A client assertion signed by the client's private key: `iss` = `sub` = `client_id`, `aud` the AS **issuer identifier** as its sole value, plus `jti`, `iat`, `exp` and `typ` `client-authentication+jwt` (draft-ietf-oauth-rfc7523bis-11). RFC 7523's token-endpoint `aud` stays selectable. |
| `attest_jwt_client_auth` | draft-ietf-oauth-attestation-based-client-auth-**12** (a DRAFT): the Client Attestation in `OAuth-Client-Attestation`, and a PoP by its `cnf` key in `OAuth-Client-Attestation-PoP`. The PoP carries `aud` (the issuer), `jti`, `iat`, and the server's challenge when it sent one. A `use_attestation_challenge` answer is retried once with the fresh challenge. |

**The default** is the first method in the authorization server's
`token_endpoint_auth_methods_supported` that this debugger implements, in
the server's order. With no list, it is `none`.

## Where it is set, and what is kept

Step 1 has a **Client Authentication** pane (`vc_client_auth_pane.js`)
with the method, the assertion's `alg`, `aud`, `typ` and `kid`, a client
key (generated or pasted, with its public JWKS shown for registration),
and the attestation with its instance key. **Make one** signs an
attestation with a local attester key, and shows that attester's JWKS for
a server to be told to trust. A real attestation comes from the wallet
provider.

- **The client secret is never stored,** in any storage. It's typed into
  `vc_client_secret` on each page that sends it (steps 2 and 4), or into
  the OAuth 2.0 page's own secret field for the code exchange.
  `secret_storage.js` lists the field id, so `tests/secret_storage_engine.js`
  fails on any write of it.
- **The client private key, the attestation, its instance key and a local
  attester key are key material:** declared `keypair` in
  `models/storage/vc_client_auth_pane.tsp`, and kept only while **Keep the
  client keys in this browser** is checked (it is by default). Clearing the
  box removes them on the spot; a page that then needs one offers a paste
  field.
- **The settings are ordinary:** the method, alg, aud choice, `kid` and
  `typ`.

## Shown requests

Steps 2 and 4 show the Token Request exactly as it will be sent, with the
secret replaced by `<client_secret>`. That includes
`Authorization: Basic base64(<client_id>:<client_secret>)`,
`client_assertion=…`, and the two attestation headers.

The code exchange on `oauth2_oidc_2.html` records what left on that page's
HTTP tab:
- `client_secret_basic` and `client_secret_post` are that page's own auth
  styles, which the VC flow sets.
- The JWT methods go in the body: through the api they ride as custom
  parameters, which the api forwards.
- **The Client Attestation needs Front End** (*Initiate call from*),
  because it travels in request headers, which the api does not forward.
  The page says so rather than sending without it.

## Tests

| Test | What it checks |
|---|---|
| `tests/client_auth_engine.js` | Each method's wire form from the text that defines it: RFC 6749 §2.3.1's own Basic example and Appendix B encoding; 7523bis claims, `typ` and `aud`, with HS256, ES256, EdDSA and PS256 verified by node; the attestation's and the PoP's `typ` and claims, signed by the `cnf` key. Plus the refusals, and that no shown request ever carries the secret. |
| `tests/vc_issuance_client_auth.js` | In Chrome, against a **confidential** client the job provisions on iya-sts through `/admin-api` (never assumed to exist): `client_secret_basic` (and a wrong secret refused), `client_secret_post`, `private_key_jwt` (its JWKS registered on the client), and a Client Attestation signed by node's crypto with an attester iya-sts is told to trust for the job. It asserts that no storage holds the secret, and holds the `sts-vc` lock. |
