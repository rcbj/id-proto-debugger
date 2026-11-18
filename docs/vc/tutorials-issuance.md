# Tutorials: receiving a credential

Each tutorial below receives a credential from an OpenID4VCI Credential
Issuer with the debugger as the wallet. Start with
[tutorial-issuer-discovery.md](tutorial-issuer-discovery.md), which reads
the issuer's metadata; every value used here comes from that metadata or
from the offer the issuer makes you, so the steps are the same for any
spec-compliant issuer.

**What each needs from the issuer.** A pre-authorized offer needs an
account at the issuer (the offer is made for a person the issuer knows) but
no client registration — an issuer that advertises
`pre-authorized_grant_anonymous_access_supported` redeems the code for a
wallet it has never seen. The Authorization Code flow needs the wallet's
`client_id` registered at the authorization server with this deployment's
`/callback` as a redirect URI. These tutorials have no screenshots in this
edition; the screens are described in
[reference-issuance.md](reference-issuance.md).

- [Receive an SD-JWT VC by pre-authorized code, with a Transaction Code](#receive-an-sd-jwt-vc-by-pre-authorized-code-with-a-transaction-code)
- [Take an offer from its QR code](#take-an-offer-from-its-qr-code)
- [Receive a credential by authorization code](#receive-a-credential-by-authorization-code)
- [Ask for only some of the claims](#ask-for-only-some-of-the-claims)
- [Sender-constrain the token with DPoP](#sender-constrain-the-token-with-dpop)
- [A credential that is not ready yet (deferred)](#a-credential-that-is-not-ready-yet-deferred)
- [Refresh a credential](#refresh-a-credential)
- [Keep no private keys in the browser](#keep-no-private-keys-in-the-browser)
- [Client authentication: private_key_jwt and a Client Attestation](#client-authentication-private_key_jwt-and-a-client-attestation)
- [Other formats: jwt_vc_json, ldp_vc and the rest](#other-formats-jwt_vc_json-ldp_vc-and-the-rest)

## Receive an SD-JWT VC by pre-authorized code, with a Transaction Code

OpenID4VCI Appendix H.2, §4.1.1, §6.1.

1. On step 0, set **Issuer website URL** to the page where your issuer makes
   offers (an account page, a portal) and press **Save**, then choose
   **Scan a code, type a transaction code**. The debugger opens that page.
2. On the issuer's page, sign in and ask for a pre-authorized offer of the
   credential you want. It shows an `openid-credential-offer://` link or QR
   code, and — separately — a **Transaction Code**.
3. Back on step 1, paste the offer into **Receive a Credential Offer** and
   press **Take this offer**. The **Credential Offer** pane appears, naming
   the issuer, the `credential_configuration_ids` and the
   `pre-authorized_code` grant with its `tx_code` description, and the
   page retrieves the issuer's and the authorization server's metadata on
   its own.
4. Press **Start Issuance**. A pre-authorized offer skips the sign-in and
   goes straight to step 2.
5. In **Token Request (pre-authorized code)**, type the Transaction Code.
   The hint says the length and input mode the offer declared; the code is
   never stored. **The call** shows the request exactly as it will be sent.
   Press **Send the Token Request**.
6. The access token appears. **OID4VCI Credential Request** shows the holder
   key the wallet generated, the `c_nonce` it fetched from the Nonce
   Endpoint, the `openid4vci-proof+jwt` key proof and the request body.
   Press **Approve and Request Credential**.
7. Step 3 shows the SD-JWT VC: the issuer-signed JWT with its **Checks**,
   one row per Disclosure, and the resulting claim set. Every check should
   pass — in particular that `cnf` names the key the wallet generated in
   step 6, and that every Disclosure's digest is in `_sd`.
8. Optionally, **Notify the Issuer** with `credential_accepted` (§11).

The credential is now held (`sdjwtvc_credential`) and ready to present —
see [tutorial-present-to-verifier.md](tutorial-present-to-verifier.md).

## Take an offer from its QR code

Appendix H.2. In step 3 above, instead of pasting text, choose an image of
the QR code (a screenshot, a photo, or the SVG the issuer drew) in **Or its
QR code**. The page decodes it locally, fills the box with what it encodes
and says so; press **Take this offer** as before.

## Receive a credential by authorization code

Appendix H.6 (from the wallet) or H.1 (from an offer); §5.

1. Register the wallet at the issuer's authorization server — however that
   server registers clients — as a public client (or a confidential one, see
   below) with this deployment's `/callback` as a redirect URI.
2. Do [tutorial-issuer-discovery.md](tutorial-issuer-discovery.md). Set
   `client_id` in **Configuration Parameters** to your registration and
   press **Save**. Choose the credential in **Credential to request**.
3. In **Authorize Issuance**, choose how to ask: `scope` (the
   configuration's `scope`) or `authorization_details` (RFC 9396). With an
   offer that carried `issuer_state`, it is sent back automatically.
4. Press **Start Issuance**. The workflow drives the OAuth 2.0 pages
   (`oauth2_oidc_1.html?sdjwtvc=1`): it sends the authorization request with
   PKCE, you sign in at the authorization server, and the code is exchanged
   for tokens without further clicks. Those pages are described in
   [../oauth2-oidc/oidc-flows.md](../oauth2-oidc/oidc-flows.md).
5. You land on step 2, with the tokens in **Tokens from the OIDC
   Authorization Code Flow**. With `authorization_details`, the token
   response grants `credential_identifiers`, and **Credential Request
   Options** names the credential by `credential_identifier` (§8.2).
6. Press **Approve and Request Credential**, and read step 3 as above.

## Ask for only some of the claims

§5.1.1. On step 1, untick claims in **Claims to Request**. The selection is
sent only when it is a strict subset of what the issuer advertises: as
`authorization_details` on the authorization request (choose
**authorization_details** in **Authorize Issuance**), or on step 2's Token
Request for a pre-authorized offer. A `scope` request cannot carry it. A
claim the issuer marks `mandatory` is included whatever you choose, and the
row says so. Step 3 then shows which claims the issuer actually put in.

## Sender-constrain the token with DPoP

RFC 9449; [../dpop.md](../dpop.md).

1. On step 2 (before the Token Request for a pre-authorized offer, or before
   step 1's **Start Issuance** to bind the authorization code with
   `dpop_jkt`), tick **Sender-constrain the token** in **DPoP**. Choose the
   proof algorithm; **Server accepts** shows the authorization server's
   `dpop_signing_alg_values_supported`, and absent means it has not said it
   supports DPoP.
2. Optionally tick **Holder of Key — bind the credential to the DPoP key**,
   so the DPoP key is also the key the credential is bound to.
3. Redeem the code and request the credential as usual. **Token binding**
   shows what the server actually answered: `token_type: DPoP` and a
   `cnf.jkt` equal to the **jkt** shown. A `DPoP-Nonce` the server demands is
   picked up and the request retried once. **Proof sent** decodes the last
   proof.

A server that ignores DPoP answers `token_type: Bearer`, and **Token
binding** shows exactly that.

## A credential that is not ready yet (deferred)

Appendix H.3; §9. Take a deferred offer from the issuer (step 0's **The
credential is not ready yet** card sends you to the issuer's page). When the
Credential Response carries a `transaction_id` instead of a credential, step
2 opens **Deferred Issuance**: the transaction, the Deferred Credential
Endpoint, the request it sends and every attempt. It polls on its own at
the `interval` the issuer asks for (5 seconds if none) and opens step 3 when
the credential arrives; **Check again now** polls immediately.

## Refresh a credential

§14.5 (implementation considerations), RFC 6749 §6.

1. From step 3, press **Refresh It (step 4)**. **The Credential You Hold**
   shows its type, validity and the key it is bound to.
2. **Refresh the Access Token**: press **Send the Refresh Request**. A
   confidential client authenticates (the **Client Authentication** pane).
   An authorization server need not issue a refresh token; when it did not,
   the page says so.
3. **Ask the Credential Endpoint Again**: keep **Holder key** at *Reuse the
   key the credential is already bound to* to get a replacement, or choose
   *Generate a new holder key pair* to bind a new one.
   Press **Request a Refreshed Credential**. Nothing you hold changes yet.
4. **What Changed** compares the two: the issuer may only re-sign, or may
   change claims and validity. Choose **Replace the credential I hold** or
   **Discard the refreshed one**.
5. **Credential History** logs every attempt — issuance, token refresh,
   Credential Request, deferred poll — with its outcome. **Oldest**,
   **Older**, **Newer** and **Latest** walk the generations, and making one
   current puts that credential and its holder key back in hand.

## Keep no private keys in the browser

On step 2, untick **Save this holder key pair in browser localStorage** before approving, and press
**Download Key Pair** to keep the file yourself. The holder private key is
then never written to storage, and every Credential History row loses its
private key at once. When a later page needs it — step 4's re-issuance with
the same key, or presentation step 2 — it shows a **Holder private key**
box; paste the downloaded file or a bare private JWK. The pasted key is
never stored.

## Client authentication: private_key_jwt and a Client Attestation

[../vc-client-auth.md](../vc-client-auth.md). For an authorization server
that requires the wallet to authenticate:

1. On step 1, in **Client Authentication**, choose the method.
   - `client_secret_basic` / `client_secret_post` / `client_secret_jwt`: the
     secret is typed on each page that sends it (steps 2 and 4, or the OAuth
     page's own field for the code exchange) and is never stored.
   - `private_key_jwt`: press **Generate** (or paste your key), and register
     the **Public JWKS** shown with the authorization server. Choose the
     assertion's `aud`: the issuer identifier (*draft-ietf-oauth-rfc7523bis-11*,
     a draft) or the token endpoint (RFC 7523).
   - `attest_jwt_client_auth` (*draft-ietf-oauth-attestation-based-client-auth-12*,
     a draft): paste the Client Attestation your wallet provider issued and
     its instance key, or press **Make one** to sign one with a local
     attester and tell the server to trust the **Attester JWKS** shown.
2. Proceed as in the tutorials above. Step 2 and step 4 show the Token
   Request exactly as sent — the assertion, or the
   `OAuth-Client-Attestation` and `-PoP` headers — with any secret masked.
   For the code exchange with an attestation, set **Initiate call from:
   Front End** on the OAuth page, because the api does not forward request
   headers.

## Other formats: jwt_vc_json, ldp_vc and the rest

Choose the configuration in **Credential to request** (or take an offer for
it) and follow the same steps. What changes is the holder binding and step
3's checks:

| Format | Holder binding | Guide |
|---|---|---|
| `jwt_vc_json` | `cnf.jwk` | [format-jwt-vc-json.md](format-jwt-vc-json.md) |
| `ldp_vc` | `credentialSubject.id`, a `did:jwk` of the holder key | [format-ldp-vc.md](format-ldp-vc.md) |
| `mso_mdoc` | the device key in the MSO | [format-mdoc.md](format-mdoc.md) |
| `vc+jwt`, `vc+sd-jwt`, `vc+cose` | `cnf` | [format-vc-jose-cose.md](format-vc-jose-cose.md) |
| `jpt`, `sd-cwt` (drafts) | per format | [format-sd-cwt-jwp.md](format-sd-cwt-jwp.md) |
| `anoncreds` | a link secret | [format-anoncreds.md](format-anoncreds.md) |

An `ldp_vc` whose issuer is named by a DID has its proof checked against the
DID document step 1 resolved; **Use DIDs for this credential** is on by
default for that format.
