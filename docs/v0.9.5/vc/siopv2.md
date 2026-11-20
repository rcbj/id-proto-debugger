# SIOPv2 — a self-issued ID Token from the wallet

[Self-Issued OpenID Provider v2][siopv2] lets the **wallet itself** act as an
OpenID Provider: instead of a provider signing an ID Token about you, the
wallet signs one about the key it holds, with `iss` equal to `sub`. Combined
with OpenID4VP (`response_type=vp_token id_token`), the Verifier gets a
presentation **and** an authenticated subject in one answer.

SIOPv2 is the third card on the wallet's step 0 (`vp_protocol_siopv2`). The
debugger's own Verifier page does not ask for ID Tokens, so this needs a
Verifier that does; the suite uses iya-sts's, and any SIOPv2 relying party
works.

## What the wallet requires of the request

On top of the OpenID4VP rules ([openid4vp.md](openid4vp.md)), step 1 refuses
a SIOPv2 request unless:

| Rule | Requires |
|---|---|
| `SIOPv2: id_token` | `response_type` includes `id_token` |
| `SIOPv2: scope openid` | `scope` includes `openid` |
| `SIOPv2: subject syntax` | The Verifier's `subject_syntax_types_supported` includes `urn:ietf:params:oauth:jwk-thumbprint`, `did:jwk` or `did:key` (none listed means the JWK Thumbprint syntax) |

An ID Token on its own (`response_type=id_token`) is accepted with an
advisory, and a DCQL query is then not required.

## The ID Token

Step 2's **Self-Issued ID Token** pane shows the token before it is sent:

- **Subject syntax** — JWK Thumbprint (with the key in `sub_jwk`), `did:jwk`
  or `did:key`. Only syntaxes the Verifier lists are offered.
- **Payload** — `iss` = `sub`, `aud` (the Verifier), `nonce`, `iat`, and
  `exp` five minutes later (SIOPv2 §11).
- **Signing key** — next to a presentation, the token is signed by the
  **same key the credential is bound to**, so the Verifier can check that
  the subject who authenticated is the holder who presented. On its own, the
  token may instead use a **pairwise key** for this Verifier
  (`vp_siop_pairwise`), so different Verifiers see different subjects. The
  pairwise private keys are key material, kept only while *keep pairwise
  keys* is ticked.

The answer travels by any response mode the wallet supports, including
`post` (SIOPv2's own) and `form_post`, where the **browser** carries it and
the wallet never sees the Verifier's reply. Step 3 re-checks the token
(**The Wallet's Own Checks**): `iss` equals `sub`, `aud` is the Verifier,
`nonce` is the request's, `sub` is the RFC 7638 thumbprint of `sub_jwk`
(for that syntax), the signature verifies with the key the subject names,
and — beside a presentation — that this key **is** the key the presentation
is bound to ("Same holder").

**Refuse** on step 2 sends `user_cancelled` for an ID Token on its own, or
`subject_syntax_types_not_supported`, back the way an answer would travel.

Field details: [reference-presentation.md](reference-presentation.md#the-self-issued-id-token-siopv2).
Developer notes: [../sd-jwt-vc-presentation.md](../sd-jwt-vc-presentation.md).

[siopv2]: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
